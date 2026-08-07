from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from ..auth import current_analyst
from ..db import fetch_all, fetch_one

router = APIRouter(prefix="/api/entities", tags=["entities"])


@router.get("")
async def list_entities(
    verdict: str | None = Query(None),
    kind: str | None = Query(None),
    limit: int = Query(100, le=500),
    _: dict = Depends(current_analyst),
) -> list[dict]:
    wheres = []
    params: list = []
    if verdict:
        wheres.append("verdict = %s")
        params.append(verdict)
    if kind:
        wheres.append("kind = %s")
        params.append(kind)

    where_clause = ("WHERE " + " AND ".join(wheres)) if wheres else ""
    params.append(limit)

    rows = await fetch_all(
        f"""
        SELECT id, kind, value, verdict, reasoning, risk_score,
               times_seen, first_seen, last_seen, cleared_count
        FROM entity_memory
        {where_clause}
        ORDER BY risk_score DESC NULLS LAST, times_seen DESC
        LIMIT %s
        """,
        params or None,
    )
    return [
        {
            "id": str(r["id"]),
            "kind": r["kind"],
            "value": r["value"],
            "verdict": r["verdict"],
            "reasoning": r["reasoning"],
            "riskScore": r["risk_score"],
            "timesSeen": r["times_seen"],
            "firstSeen": r["first_seen"].strftime("%Y-%m-%d") if r["first_seen"] else None,
            "lastSeen": r["last_seen"].strftime("%Y-%m-%d") if r["last_seen"] else None,
            "clearedCount": r["cleared_count"],
        }
        for r in rows
    ]


@router.get("/stats")
async def entity_stats(_: dict = Depends(current_analyst)) -> dict:
    rows = await fetch_all("SELECT verdict, COUNT(*) AS n FROM entity_memory GROUP BY verdict")
    total = await fetch_one("SELECT COUNT(*) AS n FROM entity_memory")
    counts = {r["verdict"]: r["n"] for r in rows}
    return {
        "total": total["n"] if total else 0,
        "malicious": counts.get("malicious", 0),
        "suspicious": counts.get("suspicious", 0),
        "benign": counts.get("benign", 0),
        "unknown": counts.get("unknown", 0),
    }
