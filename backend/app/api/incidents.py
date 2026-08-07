from __future__ import annotations

import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from ..auth import current_analyst
from ..db import fetch_all, fetch_one, execute
from ..models import IncidentDetail, IncidentSummary, QueueStats

router = APIRouter(prefix="/api/incidents", tags=["incidents"])
log = logging.getLogger(__name__)


def _fmt(dt) -> str | None:
    return dt.strftime("%Y-%m-%d %H:%M") if dt else None


def _fmt_full(dt) -> str | None:
    return dt.isoformat() if dt else None


@router.get("/stats", response_model=QueueStats)
async def stats(_: dict = Depends(current_analyst)) -> QueueStats:
    rows = await fetch_all(
        """
        SELECT status, COUNT(*) AS n FROM incident GROUP BY status
        """
    )
    counts = {r["status"]: r["n"] for r in rows}
    alert_count = await fetch_one("SELECT COUNT(*) AS n FROM alert")
    return QueueStats(
        open=counts.get("triage", 0),
        investigating=counts.get("investigating", 0),
        closed=counts.get("closed", 0) + counts.get("contained", 0),
        auto_cleared=counts.get("false_positive", 0),
        total_alerts=alert_count["n"] if alert_count else 0,
        total_events=0,
    )


@router.get("", response_model=list[IncidentSummary])
async def list_incidents(_: dict = Depends(current_analyst)) -> list[IncidentSummary]:
    rows = await fetch_all(
        """
        SELECT
            i.id, i.ref, i.title, i.severity, i.status,
            i.host, i.primary_user, i.attack_technique, i.summary,
            i.opened_at,
            COUNT(a.id) AS alert_count
        FROM incident i
        LEFT JOIN alert a ON a.incident_id = i.id
        GROUP BY i.id, i.ref, i.title, i.severity, i.status,
                 i.host, i.primary_user, i.attack_technique, i.summary, i.opened_at
        ORDER BY
            CASE i.severity
                WHEN 'critical' THEN 5
                WHEN 'high'     THEN 4
                WHEN 'medium'   THEN 3
                WHEN 'low'      THEN 2
                ELSE 1
            END DESC,
            i.opened_at DESC
        """
    )
    return [
        IncidentSummary(
            id=str(r["id"]),
            ref=r["ref"],
            title=r["title"],
            severity=r["severity"],
            status=r["status"],
            host=r["host"],
            primary_user=r["primary_user"],
            attack_technique=r["attack_technique"],
            alert_count=r["alert_count"],
            opened_at=_fmt(r["opened_at"]) or "",
            summary=r["summary"],
        )
        for r in rows
    ]


@router.get("/{incident_id}", response_model=IncidentDetail)
async def get_incident(incident_id: str, _: dict = Depends(current_analyst)) -> IncidentDetail:
    inc = await fetch_one(
        """
        SELECT i.id, i.ref, i.title, i.severity, i.status,
               i.host, i.primary_user, i.summary, i.root_cause, i.report,
               i.attack_technique, i.opened_at, i.closed_at,
               COUNT(a.id) AS alert_count
        FROM incident i
        LEFT JOIN alert a ON a.incident_id = i.id
        WHERE i.id = %s OR i.ref = %s
        GROUP BY i.id, i.ref, i.title, i.severity, i.status,
                 i.host, i.primary_user, i.summary, i.root_cause, i.report,
                 i.attack_technique, i.opened_at, i.closed_at
        """,
        (incident_id, incident_id.upper()),
    )
    if inc is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    inc_id = str(inc["id"])

    hypotheses = await fetch_all(
        """
        SELECT h.id, h.statement, h.status, h.confidence, h.rationale,
               h.created_at, h.resolved_at,
               COUNT(CASE WHEN e.supports THEN 1 END) AS supporting,
               COUNT(CASE WHEN NOT e.supports THEN 1 END) AS contradicting
        FROM hypothesis h
        LEFT JOIN evidence e ON e.hypothesis_id = h.id
        WHERE h.incident_id = %s
        GROUP BY h.id, h.statement, h.status, h.confidence, h.rationale,
                 h.created_at, h.resolved_at
        ORDER BY h.confidence DESC NULLS LAST
        """,
        (inc_id,),
    )

    timeline = await fetch_all(
        "SELECT seq, occurred_at, actor, action, attack_technique "
        "FROM timeline_event WHERE incident_id = %s ORDER BY seq",
        (inc_id,),
    )

    evidence = await fetch_all(
        "SELECT id, claim, supports, source_tool, created_at "
        "FROM evidence WHERE incident_id = %s ORDER BY created_at",
        (inc_id,),
    )

    entities = await fetch_all(
        """
        SELECT em.id, em.kind, em.value, em.verdict, em.reasoning,
               em.risk_score, em.times_seen, em.first_seen, em.cleared_count
        FROM entity_memory em
        JOIN entity_sighting es ON es.entity_id = em.id
        WHERE es.incident_id = %s
        ORDER BY em.risk_score DESC NULLS LAST
        """,
        (inc_id,),
    )

    # Vector similarity search
    similar = None
    inc_embedding_row = await fetch_one(
        "SELECT embedding FROM incident WHERE id = %s AND embedding IS NOT NULL",
        (inc_id,),
    )
    if inc_embedding_row and inc_embedding_row["embedding"] is not None:
        vec_literal = str(inc_embedding_row["embedding"])
        sim_row = await fetch_one(
            f"""
            SELECT ref, title,
                   embedding <-> '{vec_literal}'::VECTOR AS distance
            FROM incident
            WHERE id != %s
              AND status IN ('closed', 'false_positive', 'contained')
              AND embedding IS NOT NULL
            ORDER BY distance
            LIMIT 1
            """,
            (inc_id,),
        )
        if sim_row:
            from ..models import SimilarIncident
            similar = SimilarIncident(
                ref=sim_row["ref"],
                title=sim_row["title"],
                similarity=round(1 - float(sim_row["distance"]), 3),
            )

    return IncidentDetail(
        id=inc_id,
        ref=inc["ref"],
        title=inc["title"],
        severity=inc["severity"],
        status=inc["status"],
        host=inc["host"],
        primary_user=inc["primary_user"],
        summary=inc["summary"],
        root_cause=inc["root_cause"],
        report=inc["report"],
        attack_technique=inc["attack_technique"],
        opened_at=_fmt_full(inc["opened_at"]) or "",
        closed_at=_fmt_full(inc["closed_at"]),
        alert_count=inc["alert_count"],
        hypotheses=[
            {
                "id": str(h["id"]),
                "statement": h["statement"],
                "status": h["status"],
                "confidence": float(h["confidence"]) if h["confidence"] is not None else None,
                "supporting": h["supporting"],
                "contradicting": h["contradicting"],
                "note": h["rationale"],
                "created_at": _fmt_full(h["created_at"]) or "",
                "resolved_at": _fmt_full(h["resolved_at"]),
            }
            for h in hypotheses
        ],
        timeline=[
            {
                "seq": t["seq"],
                "occurred_at": _fmt_full(t["occurred_at"]) or "",
                "actor": t["actor"],
                "action": t["action"],
                "attack_technique": t["attack_technique"],
            }
            for t in timeline
        ],
        evidence=[
            {
                "id": str(e["id"]),
                "claim": e["claim"],
                "supports": e["supports"],
                "source_tool": e["source_tool"],
                "created_at": _fmt_full(e["created_at"]) or "",
            }
            for e in evidence
        ],
        entities=[
            {
                "id": str(e["id"]),
                "kind": e["kind"],
                "value": e["value"],
                "verdict": e["verdict"],
                "reasoning": e["reasoning"],
                "risk_score": e["risk_score"],
                "times_seen": e["times_seen"],
                "first_seen": _fmt(e["first_seen"]) or "",
                "cleared_count": e["cleared_count"],
            }
            for e in entities
        ],
        similar=similar,
    )


@router.post("/{incident_id}/investigate", status_code=202)
async def start_investigation(
    incident_id: str,
    background_tasks: BackgroundTasks,
    analyst: dict = Depends(current_analyst),
) -> dict:
    from ..agent.loop import run_investigation

    inc = await fetch_one(
        "SELECT id, ref, status FROM incident WHERE id = %s OR ref = %s",
        (incident_id, incident_id.upper()),
    )
    if inc is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    if inc["status"] == "investigating":
        return {"status": "investigating", "message": "Already running"}
    if inc["status"] in ("closed", "false_positive", "contained"):
        raise HTTPException(status_code=409, detail=f"Incident already {inc['status']}")

    await execute(
        "UPDATE incident SET status = 'investigating' WHERE id = %s", (str(inc["id"]),)
    )
    background_tasks.add_task(run_investigation, str(inc["id"]))
    log.info("Investigation started for %s by %s", inc["ref"], analyst["email"])
    return {"status": "investigating", "incident_id": str(inc["id"]), "ref": inc["ref"]}
