"""Run the full pipeline and print the resulting queue.

Reads the corpus, runs detectors, correlates alerts into incidents, and shows
what an analyst would see. This is the queue the frontend will render once the
memory layer is connected.

Usage:
    python scripts/triage.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.ingest.correlate import correlate  # noqa: E402
from app.ingest.detectors import run_detectors  # noqa: E402
from app.ingest.evtx_reader import read_directory  # noqa: E402

RAW = ROOT / "data" / "raw"


def main() -> int:
    if not RAW.exists() or not any(RAW.glob("*.evtx")):
        print("No samples. Run: python scripts/fetch_datasets.py")
        return 1

    events = read_directory(RAW)
    alerts = run_detectors(events)
    incidents = correlate(alerts)

    print(f"{len(events)} events -> {len(alerts)} alerts -> {len(incidents)} incidents\n")

    for incident in incidents:
        span = (incident.closed_at - incident.opened_at).total_seconds()
        print(f"{incident.ref}  [{incident.severity:<8}] {incident.title}")
        print(
            f"          host {incident.host}"
            f"   user {', '.join(incident.users) or '-'}"
        )
        print(
            f"          {incident.opened_at:%Y-%m-%d %H:%M:%S}"
            f"  span {span:.0f}s  {len(incident.alerts)} alerts"
        )
        print(f"          tactics: {', '.join(incident.tactics)}")

        for entry in incident.timeline:
            repeat = f"  (x{entry.occurrences})" if entry.occurrences > 1 else ""
            print(
                f"            {entry.seq}. {entry.occurred_at:%H:%M:%S}"
                f"  {entry.technique:<10} {entry.action[:64]}{repeat}"
            )
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
