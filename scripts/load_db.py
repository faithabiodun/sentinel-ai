"""Load the pipeline output into CockroachDB.

Runs the real ingestion pipeline and persists every incident, alert,
hypothesis, and timeline entry to the database. Safe to re-run:
incidents are inserted with ON CONFLICT DO NOTHING keyed on the ref.

Usage:
    python scripts/load_db.py
    python scripts/load_db.py --force   # re-insert everything (drops first)
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

RAW = ROOT / "data" / "raw"


def main() -> int:
    parser = argparse.ArgumentParser(description="Load pipeline output into CockroachDB")
    parser.add_argument("--force", action="store_true", help="Drop existing data first")
    args = parser.parse_args()

    from app.config import settings
    from app.ingest.correlate import correlate
    from app.ingest.detectors import run_detectors
    from app.ingest.evtx_reader import read_directory

    if not settings.database_url:
        print("DATABASE_URL is not set. Copy .env.example to .env and fill it in.")
        return 1

    if not RAW.exists() or not any(RAW.glob("*.evtx")):
        print("No samples. Run: python scripts/fetch_datasets.py")
        return 1

    print("Running pipeline…")
    events = read_directory(RAW)
    alerts = run_detectors(events)
    incidents = correlate(alerts)
    print(f"{len(events)} events → {len(alerts)} alerts → {len(incidents)} incidents\n")

    with psycopg.connect(settings.database_url) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            if args.force:
                print("Dropping existing data…")
                cur.execute("DELETE FROM entity_sighting")
                cur.execute("DELETE FROM entity_memory")
                cur.execute("DELETE FROM evidence")
                cur.execute("DELETE FROM timeline_event")
                cur.execute("DELETE FROM tool_run")
                cur.execute("DELETE FROM hypothesis")
                cur.execute("DELETE FROM alert")
                cur.execute("DELETE FROM incident")

            for number, inc in enumerate(incidents, 1):
                ref = f"INC-{number:04d}"
                users_str = ", ".join(inc.users) or None

                # Insert incident
                cur.execute(
                    """
                    INSERT INTO incident
                        (ref, title, severity, status, host, primary_user, summary, opened_at, closed_at)
                    VALUES (%s, %s, %s, 'triage', %s, %s, %s, %s, %s)
                    ON CONFLICT (ref) DO NOTHING
                    RETURNING id
                    """,
                    (
                        ref,
                        inc.title,
                        inc.severity,
                        inc.host,
                        users_str,
                        inc.summary,
                        inc.opened_at,
                        inc.closed_at,
                    ),
                )
                row = cur.fetchone()
                if row is None:
                    # Already exists — fetch the id
                    cur.execute("SELECT id FROM incident WHERE ref = %s", (ref,))
                    row = cur.fetchone()
                incident_id = str(row[0])

                # Insert alerts
                for alert in inc.alerts:
                    event = alert.event
                    raw = json.dumps(event.raw)
                    cur.execute(
                        """
                        INSERT INTO alert
                            (source, event_id, rule, summary, raw, host, user_principal,
                             observed_at, incident_id)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            event.source,
                            event.event_id,
                            alert.rule,
                            alert.summary,
                            raw,
                            event.host,
                            event.user,
                            event.observed_at,
                            incident_id,
                        ),
                    )

                # Insert hypotheses
                hyp_ids: list[str] = []
                for hyp in inc.hypotheses:
                    cur.execute(
                        """
                        INSERT INTO hypothesis
                            (incident_id, statement, rationale, status, confidence)
                        VALUES (%s, %s, %s, 'open', %s)
                        RETURNING id
                        """,
                        (
                            incident_id,
                            hyp.statement,
                            hyp.note,
                            hyp.confidence,
                        ),
                    )
                    hyp_ids.append(str(cur.fetchone()[0]))

                # Insert timeline
                for entry in inc.timeline:
                    cur.execute(
                        """
                        INSERT INTO timeline_event
                            (incident_id, seq, occurred_at, actor, action,
                             attack_technique, source_alert_id)
                        VALUES (%s, %s, %s, %s, %s, %s, NULL)
                        """,
                        (
                            incident_id,
                            entry.seq,
                            entry.occurred_at,
                            entry.actor,
                            entry.action,
                            entry.technique,
                        ),
                    )

                print(
                    f"  {ref}  [{inc.severity:<8}]  {inc.title[:60]}"
                    f"  ({len(inc.alerts)} alerts, {len(inc.hypotheses)} hypotheses)"
                )

    print(f"\nLoaded {len(incidents)} incidents into CockroachDB.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
