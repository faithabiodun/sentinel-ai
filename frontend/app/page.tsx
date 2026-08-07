"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { incidents as api, type IncidentSummary, type QueueStats } from "@/lib/api";

const statusLabel: Record<string, string> = {
  triage: "triage",
  investigating: "investigating",
  contained: "contained",
  closed: "closed",
  false_positive: "auto-cleared",
};

export default function QueuePage() {
  const [rows, setRows] = useState<IncidentSummary[]>([]);
  const [stats, setStats] = useState<QueueStats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([api.list(), api.stats()])
      .then(([inc, s]) => {
        setRows(inc);
        setStats(s);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="state-loading">Loading queue…</div>;

  return (
    <>
      <div className="page-head">
        <h1 className="page-title">Triage queue</h1>
        <p className="page-sub">
          Ordered by severity, then by what the agent has not yet ruled out.
        </p>
      </div>

      {error && <div className="state-error">{error}</div>}

      {stats && (
        <div className="counters">
          <div>
            <div className="counter-n">{stats.open + stats.investigating}</div>
            <div className="counter-l">Open</div>
          </div>
          <div>
            <div className="counter-n">{stats.investigating}</div>
            <div className="counter-l">Investigating</div>
          </div>
          <div>
            <div className="counter-n">{stats.total_alerts}</div>
            <div className="counter-l">Alerts</div>
          </div>
          <div>
            <div className="counter-n" data-tone="cleared">{stats.auto_cleared}</div>
            <div className="counter-l">Auto-cleared</div>
          </div>
        </div>
      )}

      <div className="queue-head">
        <span>Ref</span>
        <span>Incident</span>
        <span>Host</span>
        <span>Technique</span>
        <span>Status</span>
        <span>Opened</span>
      </div>

      <div className="queue">
        {rows.map((inc) => (
          <Link
            key={inc.ref}
            href={`/incidents/${inc.ref}`}
            className="row"
            data-sev={inc.severity}
          >
            <div className="row-top">
              <span className="row-ref">{inc.ref}</span>
              <span className="row-title">{inc.title}</span>
            </div>
            <div className="row-meta">
              <span className="mono">{(inc.host ?? "—").split(".")[0]}</span>
              <span className="mono">{inc.attack_technique ?? "—"}</span>
              <span className="pill" data-t={inc.status}>
                {statusLabel[inc.status] ?? inc.status}
              </span>
              <span className="row-time">{inc.opened_at.slice(0, 16)}</span>
            </div>
          </Link>
        ))}
      </div>

      {rows.length === 0 && !error && (
        <p className="empty">
          No incidents in the database yet. Run{" "}
          <code>python scripts/load_db.py</code> to load the corpus.
        </p>
      )}

      <p className="provenance">
        Derived from real Windows events captured during known attack techniques
        (EVTX-ATTACK-SAMPLES). No synthetic telemetry — technique labels ship
        with the corpus, so detection is measured rather than asserted.
      </p>
    </>
  );
}
