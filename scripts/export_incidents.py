"""Export the pipeline's output for the frontend.

Runs the real pipeline over the real corpus and writes what it produced to
frontend/lib/incidents.json. Nothing is hand-written: every incident, timeline
entry and hypothesis here came out of detectors run against attack telemetry
this project did not author.

Regenerate after changing detectors or correlation:
    python scripts/export_incidents.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.ingest.correlate import correlate  # noqa: E402
from app.ingest.detectors import run_detectors  # noqa: E402
from app.ingest.evtx_reader import read_directory  # noqa: E402

RAW = ROOT / "data" / "raw"
OUT = ROOT / "frontend" / "lib" / "incidents.json"


def main() -> int:
    if not RAW.exists() or not any(RAW.glob("*.evtx")):
        print("No samples. Run: python scripts/fetch_datasets.py")
        return 1

    events = read_directory(RAW)
    alerts = run_detectors(events)
    incidents = correlate(alerts)

    payload = {
        "generated": {
            "events": len(events),
            "alerts": len(alerts),
            "incidents": len(incidents),
            "source": "EVTX-ATTACK-SAMPLES",
        },
        "incidents": [
            {
                "ref": incident.ref,
                "title": incident.title,
                "severity": incident.severity,
                # Everything is untriaged: the agent that would move these
                # along does not exist yet.
                "status": "triage",
                "host": incident.host,
                "user": ", ".join(incident.users) or "—",
                "technique": incident.primary_technique,
                "tactics": incident.tactics,
                "openedAt": incident.opened_at.strftime("%Y-%m-%d %H:%M"),
                "alertCount": len(incident.alerts),
                "summary": incident.summary,
                "hypotheses": [
                    {
                        "id": f"{incident.ref}-h{n}",
                        "statement": h.statement,
                        "status": h.status,
                        "confidence": h.confidence,
                        "supporting": h.supporting,
                        "contradicting": h.contradicting,
                        "note": h.note,
                    }
                    for n, h in enumerate(incident.hypotheses, 1)
                ],
                "timeline": [
                    {
                        "seq": entry.seq,
                        "at": entry.occurred_at.strftime("%H:%M:%S"),
                        "action": entry.action,
                        "actor": entry.actor,
                        "technique": entry.technique,
                        "occurrences": entry.occurrences,
                    }
                    for entry in incident.timeline
                ],
                # Populated once entity memory exists.
                "entities": [],
            }
            for incident in incidents
        ],
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print(f"{len(events)} events -> {len(alerts)} alerts -> {len(incidents)} incidents")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
