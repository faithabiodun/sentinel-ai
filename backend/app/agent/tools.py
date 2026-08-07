"""Agent tool definitions and implementations.

Each tool has two parts:
  1. A SPEC dict in the Bedrock converse toolSpec format.
  2. An async implementation that hits CockroachDB.

The loop calls dispatch() with the tool name + input, runs the implementation,
and feeds the result back to Claude as a toolResult block.
"""
from __future__ import annotations

import json
from typing import Any

from ..db import execute, fetch_all, fetch_one

# ---------------------------------------------------------------------------
# Tool specs (sent to Claude so it knows what's available)
# ---------------------------------------------------------------------------

SPECS: list[dict] = [
    {
        "toolSpec": {
            "name": "query_entity_memory",
            "description": (
                "Look up what Sentinel already knows about an entity from past investigations. "
                "Always call this before drawing conclusions about an IP, hash, user, host, or process."
            ),
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "kind": {
                            "type": "string",
                            "enum": ["ip", "domain", "hash", "user", "host", "process"],
                        },
                        "value": {"type": "string", "description": "The entity value to look up"},
                    },
                    "required": ["kind", "value"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "search_similar_incidents",
            "description": (
                "Vector search over closed incidents to find cases with a similar pattern. "
                "Use this when you want context from prior investigations."
            ),
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "description": {
                            "type": "string",
                            "description": "Text description of the pattern you are looking for",
                        }
                    },
                    "required": ["description"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "record_evidence",
            "description": "Record a fact that supports or refutes a hypothesis.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "hypothesis_index": {
                            "type": "integer",
                            "description": "Zero-based index into the hypotheses list",
                        },
                        "claim": {"type": "string", "description": "The specific finding"},
                        "supports": {
                            "type": "boolean",
                            "description": "True if this supports the hypothesis; false if it refutes it",
                        },
                        "source": {
                            "type": "string",
                            "description": "Tool or data source that produced this evidence",
                        },
                    },
                    "required": ["hypothesis_index", "claim", "supports", "source"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "update_hypothesis",
            "description": "Move a hypothesis to confirmed or refuted once you have enough evidence.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "hypothesis_index": {"type": "integer"},
                        "status": {"type": "string", "enum": ["confirmed", "refuted"]},
                        "confidence": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 1,
                            "description": "Your confidence in this verdict (0–1)",
                        },
                        "note": {
                            "type": "string",
                            "description": "One sentence explaining your reasoning",
                        },
                    },
                    "required": ["hypothesis_index", "status", "confidence", "note"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "record_entity",
            "description": (
                "Record or update what is known about an entity. "
                "Critically: record 'benign' entities too, with the reasoning attached — "
                "a cleared false positive stays cleared across all future investigations."
            ),
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "kind": {
                            "type": "string",
                            "enum": ["ip", "domain", "hash", "user", "host", "process"],
                        },
                        "value": {"type": "string"},
                        "verdict": {
                            "type": "string",
                            "enum": ["malicious", "suspicious", "benign", "unknown"],
                        },
                        "reasoning": {
                            "type": "string",
                            "description": (
                                "Why you reached this verdict. For benign: what specifically "
                                "was ruled out and why. This is the payload that stops the same "
                                "question being raised next time."
                            ),
                        },
                        "risk_score": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 100,
                        },
                    },
                    "required": ["kind", "value", "verdict", "reasoning", "risk_score"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "close_investigation",
            "description": (
                "Close the investigation once all hypotheses are resolved. "
                "Write the full report here — it will be saved permanently."
            ),
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "root_cause": {
                            "type": "string",
                            "description": "Root cause in one concise paragraph",
                        },
                        "attack_technique": {
                            "type": "string",
                            "description": "Primary MITRE ATT&CK technique ID (e.g. T1003.001)",
                        },
                        "status": {
                            "type": "string",
                            "enum": ["closed", "false_positive", "contained"],
                        },
                        "report": {
                            "type": "string",
                            "description": "Full investigation report in markdown",
                        },
                    },
                    "required": ["root_cause", "attack_technique", "status", "report"],
                }
            },
        }
    },
]

# ---------------------------------------------------------------------------
# Implementations
# ---------------------------------------------------------------------------


async def _query_entity_memory(kind: str, value: str) -> dict:
    row = await fetch_one(
        "SELECT kind, value, verdict, reasoning, risk_score, times_seen, first_seen, cleared_count "
        "FROM entity_memory WHERE kind = %s AND value = %s",
        (kind, value),
    )
    if row is None:
        return {"found": False, "message": f"No prior knowledge of {kind} '{value}'."}
    return {
        "found": True,
        "verdict": row["verdict"],
        "reasoning": row["reasoning"],
        "risk_score": row["risk_score"],
        "times_seen": row["times_seen"],
        "first_seen": str(row["first_seen"]),
        "cleared_count": row["cleared_count"],
    }


async def _search_similar(description: str) -> dict:
    from ..agent.bedrock import embed

    vec = embed(description)
    vec_literal = "[" + ",".join(str(x) for x in vec) + "]"

    rows = await fetch_all(
        f"""
        SELECT ref, title, root_cause,
               embedding <-> '{vec_literal}'::VECTOR AS distance
        FROM incident
        WHERE status IN ('closed', 'false_positive')
          AND embedding IS NOT NULL
        ORDER BY distance
        LIMIT 3
        """,
    )
    if not rows:
        return {"found": False, "message": "No similar closed incidents found."}
    results = [
        {
            "ref": r["ref"],
            "title": r["title"],
            "root_cause": r["root_cause"],
            "similarity": round(1 - float(r["distance"]), 3),
        }
        for r in rows
    ]
    return {"found": True, "results": results}


async def _record_evidence(
    hypothesis_id: str,
    incident_id: str,
    claim: str,
    supports: bool,
    source: str,
) -> dict:
    await execute(
        """
        INSERT INTO evidence (incident_id, hypothesis_id, claim, supports, source_tool)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (incident_id, hypothesis_id, claim, supports, source),
    )
    action = "supports" if supports else "refutes"
    return {"recorded": True, "message": f"Evidence recorded: {action} hypothesis."}


async def _update_hypothesis(
    hypothesis_id: str,
    status: str,
    confidence: float,
    note: str,
) -> dict:
    from datetime import datetime, timezone

    await execute(
        """
        UPDATE hypothesis
        SET status = %s, confidence = %s, rationale = %s, resolved_at = %s
        WHERE id = %s
        """,
        (status, confidence, note, datetime.now(timezone.utc), hypothesis_id),
    )
    return {"updated": True, "hypothesis_id": hypothesis_id, "status": status}


async def _record_entity(
    incident_id: str,
    kind: str,
    value: str,
    verdict: str,
    reasoning: str,
    risk_score: int,
) -> dict:
    from datetime import datetime, timezone
    from ..agent.bedrock import embed

    vec = embed(f"{kind} {value}: {reasoning}")
    vec_literal = "[" + ",".join(str(x) for x in vec) + "]"
    now = datetime.now(timezone.utc)

    await execute(
        f"""
        INSERT INTO entity_memory (kind, value, verdict, reasoning, risk_score, embedding, first_seen, last_seen)
        VALUES (%s, %s, %s, %s, %s, '{vec_literal}'::VECTOR, %s, %s)
        ON CONFLICT (kind, value) DO UPDATE SET
            verdict      = EXCLUDED.verdict,
            reasoning    = EXCLUDED.reasoning,
            risk_score   = EXCLUDED.risk_score,
            embedding    = EXCLUDED.embedding,
            last_seen    = EXCLUDED.last_seen,
            times_seen   = entity_memory.times_seen + 1,
            cleared_count = CASE WHEN EXCLUDED.verdict = 'benign'
                            THEN entity_memory.cleared_count + 1
                            ELSE entity_memory.cleared_count END
        """,
        (kind, value, verdict, reasoning, risk_score, now, now),
    )

    entity = await fetch_one(
        "SELECT id FROM entity_memory WHERE kind = %s AND value = %s", (kind, value)
    )
    if entity:
        await execute(
            """
            INSERT INTO entity_sighting (entity_id, incident_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
            """,
            (entity["id"], incident_id),
        )

    return {"recorded": True, "kind": kind, "value": value, "verdict": verdict}


async def _close_investigation(
    incident_id: str,
    root_cause: str,
    attack_technique: str,
    status: str,
    report: str,
    summary: str,
) -> dict:
    from datetime import datetime, timezone
    from ..agent.bedrock import embed

    vec = embed(f"{summary}\n\n{root_cause}")
    vec_literal = "[" + ",".join(str(x) for x in vec) + "]"
    now = datetime.now(timezone.utc)

    await execute(
        f"""
        UPDATE incident SET
            status           = %s,
            root_cause       = %s,
            report           = %s,
            attack_technique = %s,
            closed_at        = %s,
            embedding        = '{vec_literal}'::VECTOR
        WHERE id = %s
        """,
        (status, root_cause, report, attack_technique, now, incident_id),
    )
    return {"closed": True, "incident_id": incident_id, "status": status}


# ---------------------------------------------------------------------------
# Dispatcher — called by the agent loop
# ---------------------------------------------------------------------------


async def dispatch(
    tool_name: str,
    tool_input: dict[str, Any],
    *,
    incident_id: str,
    hypothesis_ids: list[str],
    incident_summary: str,
) -> Any:
    """Route a tool call to its implementation and return a JSON-serialisable result."""

    if tool_name == "query_entity_memory":
        return await _query_entity_memory(tool_input["kind"], tool_input["value"])

    if tool_name == "search_similar_incidents":
        return await _search_similar(tool_input["description"])

    if tool_name == "record_evidence":
        idx = tool_input["hypothesis_index"]
        if idx < 0 or idx >= len(hypothesis_ids):
            return {"error": f"hypothesis_index {idx} out of range (0–{len(hypothesis_ids)-1})"}
        return await _record_evidence(
            hypothesis_ids[idx],
            incident_id,
            tool_input["claim"],
            tool_input["supports"],
            tool_input["source"],
        )

    if tool_name == "update_hypothesis":
        idx = tool_input["hypothesis_index"]
        if idx < 0 or idx >= len(hypothesis_ids):
            return {"error": f"hypothesis_index {idx} out of range"}
        return await _update_hypothesis(
            hypothesis_ids[idx],
            tool_input["status"],
            tool_input["confidence"],
            tool_input["note"],
        )

    if tool_name == "record_entity":
        return await _record_entity(
            incident_id,
            tool_input["kind"],
            tool_input["value"],
            tool_input["verdict"],
            tool_input["reasoning"],
            tool_input["risk_score"],
        )

    if tool_name == "close_investigation":
        return await _close_investigation(
            incident_id,
            tool_input["root_cause"],
            tool_input["attack_technique"],
            tool_input["status"],
            tool_input["report"],
            incident_summary,
        )

    return {"error": f"Unknown tool: {tool_name}"}
