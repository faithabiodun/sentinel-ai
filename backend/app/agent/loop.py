"""The investigation loop.

One call to run_investigation() drives a full case from 'triage' to
'closed'/'false_positive'/'contained'. It runs as a FastAPI background task
so the HTTP response returns immediately.

Flow
----
1.  Load the incident + its hypotheses from CockroachDB.
2.  Build an initial message that reads like an analyst briefing:
    incident metadata, timeline, all open hypotheses.
3.  Enter the loop:
      a. Call Claude via the Bedrock converse API.
      b. If Claude responds with plain text only → store as progress update,
         continue (Claude is thinking out loud).
      c. If Claude makes tool calls → dispatch each, return results.
      d. If Claude calls close_investigation → we're done.
      e. After MAX_ITERATIONS, force-close with a partial report.
4.  On exit: the incident record is updated by close_investigation itself.

State is checkpointed to CockroachDB by the tool implementations, so a
crash mid-investigation leaves hypotheses and evidence in a consistent state.
The next call to run_investigation on the same incident_id resumes from
where the tools left off (open hypotheses are re-added to the briefing).
"""
from __future__ import annotations

import json
import logging

from ..db import execute, fetch_all, fetch_one
from .bedrock import converse
from .tools import SPECS, dispatch

log = logging.getLogger(__name__)

MAX_ITERATIONS = 15

SYSTEM = """\
You are Sentinel, an agentic security incident investigator operating as a Tier 1/2 SOC analyst.

Your job is to investigate a security incident by:
1. Reviewing the provided incident metadata and alert timeline.
2. Querying entity memory for anything you have seen before.
3. Gathering evidence that confirms or refutes each hypothesis.
4. Recording your findings — including benign verdicts, which are as important as malicious ones.
5. Closing the investigation with a full report once all hypotheses are resolved.

Rules
-----
- Work hypothesis by hypothesis. Use record_evidence before updating_hypothesis.
- Always call query_entity_memory before drawing conclusions about an entity.
- Call search_similar_incidents when the pattern feels familiar.
- Record benign entities explicitly with reasoning — this stops the same question
  being raised in future investigations.
- Do not call close_investigation until every hypothesis is confirmed or refuted.
- Be concise in tool calls; be thorough in the close_investigation report.
"""


async def run_investigation(incident_id: str) -> None:
    """Entry point — intended to run as a FastAPI background task."""
    try:
        await _investigate(incident_id)
    except Exception:
        log.exception("Investigation failed for incident %s", incident_id)
        await execute(
            "UPDATE incident SET status = 'triage' WHERE id = %s AND status = 'investigating'",
            (incident_id,),
        )


async def _investigate(incident_id: str) -> None:
    # ------------------------------------------------------------------
    # Load incident
    # ------------------------------------------------------------------
    incident = await fetch_one(
        "SELECT id, ref, title, severity, status, host, primary_user, summary, attack_technique "
        "FROM incident WHERE id = %s",
        (incident_id,),
    )
    if incident is None:
        log.error("Incident %s not found", incident_id)
        return
    if incident["status"] not in ("triage", "investigating"):
        log.info("Incident %s already in state %s — skipping", incident_id, incident["status"])
        return

    await execute("UPDATE incident SET status = 'investigating' WHERE id = %s", (incident_id,))

    hypotheses = await fetch_all(
        "SELECT id, statement, status, confidence FROM hypothesis "
        "WHERE incident_id = %s ORDER BY confidence DESC NULLS LAST",
        (incident_id,),
    )
    hypothesis_ids = [str(h["id"]) for h in hypotheses]

    timeline = await fetch_all(
        "SELECT seq, occurred_at, actor, action, attack_technique "
        "FROM timeline_event WHERE incident_id = %s ORDER BY seq",
        (incident_id,),
    )

    alerts = await fetch_all(
        "SELECT source, rule, summary, host, user_principal, observed_at "
        "FROM alert WHERE incident_id = %s ORDER BY observed_at LIMIT 50",
        (incident_id,),
    )

    # ------------------------------------------------------------------
    # Build initial briefing
    # ------------------------------------------------------------------
    hyp_text = "\n".join(
        f"  [{i}] ({h['status']}, conf={h['confidence'] or 0:.2f}) {h['statement']}"
        for i, h in enumerate(hypotheses)
    )
    tl_text = "\n".join(
        f"  {t['seq']}. {t['occurred_at']} — {t['actor'] or '?'} — {t['action']}"
        + (f" [{t['attack_technique']}]" if t["attack_technique"] else "")
        for t in timeline
    )
    alert_text = "\n".join(
        f"  {a['source']} rule={a['rule']} host={a['host']} user={a['user_principal']} at={a['observed_at']}"
        + (f" — {a['summary']}" if a["summary"] else "")
        for a in alerts
    )

    briefing = (
        f"INCIDENT {incident['ref']}: {incident['title']}\n"
        f"Severity: {incident['severity']}  Host: {incident['host']}  "
        f"User: {incident['primary_user'] or '—'}\n"
        f"Summary: {incident['summary'] or '(none)'}\n\n"
        f"HYPOTHESES (total {len(hypotheses)}):\n{hyp_text}\n\n"
        f"TIMELINE:\n{tl_text}\n\n"
        f"ALERT DETAIL (first 50):\n{alert_text}\n\n"
        f"Open hypotheses need evidence gathered and a verdict. "
        f"Already-resolved hypotheses are listed for context."
    )

    messages: list[dict] = [{"role": "user", "content": [{"text": briefing}]}]

    # ------------------------------------------------------------------
    # Agent loop
    # ------------------------------------------------------------------
    incident_summary = incident["summary"] or incident["title"]
    done = False
    iterations = 0

    while not done and iterations < MAX_ITERATIONS:
        iterations += 1
        log.info("Incident %s — iteration %d", incident_id, iterations)

        response = converse(messages, SPECS, SYSTEM)
        output = response.get("output", {})
        message = output.get("message", {})
        content = message.get("content", [])

        # Add Claude's response to history
        messages.append({"role": "assistant", "content": content})

        stop_reason = response.get("stopReason", "")

        # No tool calls — Claude is narrating. Store progress and loop.
        if stop_reason == "end_turn":
            text = " ".join(b.get("text", "") for b in content if "text" in b).strip()
            if text:
                await execute(
                    "UPDATE incident SET summary = %s WHERE id = %s",
                    (text[:2000], incident_id),
                )
            continue

        if stop_reason != "tool_use":
            log.warning("Unexpected stop reason: %s", stop_reason)
            break

        # Dispatch tool calls
        tool_results: list[dict] = []
        for block in content:
            if "toolUse" not in block:
                continue
            tool_use = block["toolUse"]
            tool_name = tool_use["name"]
            tool_input = tool_use.get("input", {})
            tool_use_id = tool_use["toolUseId"]

            log.info("  tool: %s %s", tool_name, json.dumps(tool_input)[:120])

            result = await dispatch(
                tool_name,
                tool_input,
                incident_id=incident_id,
                hypothesis_ids=hypothesis_ids,
                incident_summary=incident_summary,
            )

            if tool_name == "close_investigation":
                done = True

            tool_results.append(
                {
                    "toolUseId": tool_use_id,
                    "content": [{"json": result}],
                }
            )

        messages.append(
            {"role": "user", "content": [{"toolResult": r} for r in tool_results]}
        )

    # ------------------------------------------------------------------
    # Safety stop — max iterations reached without close_investigation
    # ------------------------------------------------------------------
    if not done:
        log.warning("Incident %s hit max iterations (%d)", incident_id, MAX_ITERATIONS)
        open_hyps = [h for h in hypotheses if h["status"] == "open"]
        await execute(
            "UPDATE incident SET status = 'triage', summary = %s WHERE id = %s",
            (
                f"Investigation paused after {MAX_ITERATIONS} iterations. "
                f"{len(open_hyps)} hypothesis(es) still open.",
                incident_id,
            ),
        )
