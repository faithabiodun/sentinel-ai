"use client";

import { useEffect, useState } from "react";
import { entities as api, type EntityMemory, type EntityStats } from "@/lib/api";

const kindOrder = ["ip", "domain", "hash", "user", "host", "process"] as const;

export default function EntitiesPage() {
  const [rows, setRows] = useState<EntityMemory[]>([]);
  const [stats, setStats] = useState<EntityStats | null>(null);
  const [filter, setFilter] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([api.list(), api.stats()])
      .then(([ents, s]) => {
        setRows(ents);
        setStats(s);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const filtered = filter
    ? rows.filter((r) => r.verdict === filter || r.kind === filter)
    : rows;

  if (loading) return <div className="state-loading">Loading entity memory…</div>;

  return (
    <>
      <div className="page-head">
        <h1 className="page-title">Memory</h1>
        <p className="page-sub">
          What the agent knows about entities it has seen — including those it
          has already cleared.
        </p>
      </div>

      {error && <div className="state-error">{error}</div>}

      {stats && (
        <div className="counters">
          <div>
            <div className="counter-n">{stats.total}</div>
            <div className="counter-l">Tracked</div>
          </div>
          <div>
            <div className="counter-n" data-tone="cleared">{stats.benign}</div>
            <div className="counter-l">Known benign</div>
          </div>
          <div>
            <div className="counter-n" style={{ color: "var(--verdict-malicious)" }}>
              {stats.malicious}
            </div>
            <div className="counter-l">Malicious</div>
          </div>
          <div>
            <div className="counter-n">{stats.suspicious}</div>
            <div className="counter-l">Suspicious</div>
          </div>
        </div>
      )}

      {rows.length > 0 && (
        <div style={{ display: "flex", gap: "var(--space-2)", marginBottom: "var(--space-4)", flexWrap: "wrap" }}>
          {["", "malicious", "suspicious", "benign", "unknown"].map((v) => (
            <button
              key={v || "all"}
              className="pill"
              data-t={v || undefined}
              style={{
                cursor: "pointer",
                border: filter === v ? "1px solid var(--iris-400)" : "var(--border-hair)",
                background: filter === v ? "var(--iris-50)" : undefined,
              }}
              onClick={() => setFilter(v)}
            >
              {v || "All"}
            </button>
          ))}
        </div>
      )}

      {filtered.length > 0 ? (
        <section className="panel">
          {filtered.map((e) => (
            <div key={e.id} className="ent">
              <div className="ent-top">
                <span className="ent-val">{e.value}</span>
                <span className="pill" data-t={e.verdict}>{e.verdict}</span>
                <span className="mono" style={{ fontSize: "var(--text-2xs)", color: "var(--paper-400)" }}>
                  {e.kind}
                </span>
                {e.riskScore !== null && (
                  <span className="mono" style={{ fontSize: "var(--text-2xs)", color: "var(--paper-400)", marginLeft: "auto" }}>
                    risk {e.riskScore}
                  </span>
                )}
              </div>
              {e.reasoning && <p className="ent-why">{e.reasoning}</p>}
              <p className="ent-stats">
                Seen {e.timesSeen}× · first {e.firstSeen ?? "—"}
                {e.clearedCount > 0 ? ` · cleared ${e.clearedCount}×` : ""}
              </p>
            </div>
          ))}
        </section>
      ) : (
        <section className="panel">
          <p className="awaiting" style={{ margin: 0 }}>
            {rows.length > 0
              ? "No entities match the current filter."
              : "Empty, and honestly so. This is where an address, hash, user or host accumulates a verdict across every investigation that ever touched it — including benign, with the reasoning attached, so a cleared false positive stays cleared.\n\nIt fills once the agent has run against at least one incident."}
          </p>
        </section>
      )}
    </>
  );
}
