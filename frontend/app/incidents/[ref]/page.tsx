"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import { incidents as api, type IncidentDetail } from "@/lib/api";

const statusLabel: Record<string, string> = {
  triage: "triage",
  investigating: "investigating",
  contained: "contained",
  closed: "closed",
  false_positive: "auto-cleared",
};

function fmt(iso: string | null | undefined): string {
  if (!iso) return "—";
  return iso.slice(0, 16).replace("T", " ");
}

export default function IncidentPage() {
  const { ref } = useParams<{ ref: string }>();
  const [inc, setInc] = useState<IncidentDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [investigating, setInvestigating] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = useCallback(() => {
    api.get(ref).then(setInc).catch((e) => setError(e.message));
  }, [ref]);

  useEffect(() => {
    load();
  }, [load]);

  // Poll every 4 s while investigating
  useEffect(() => {
    if (inc?.status === "investigating") {
      pollRef.current = setInterval(load, 4000);
    } else {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
      setInvestigating(false);
    }
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [inc?.status, load]);

  async function startInvestigation() {
    if (!inc) return;
    setInvestigating(true);
    try {
      await api.investigate(inc.ref);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to start investigation");
      setInvestigating(false);
    }
  }

  if (error) return (
    <>
      <Link href="/" className="back">← Queue</Link>
      <div className="state-error">{error}</div>
    </>
  );

  if (!inc) return <div className="state-loading">Loading…</div>;

  const awaitingAgent = inc.hypotheses.every((h) => h.status === "open");
  const isInvestigating = inc.status === "investigating";
  const canInvestigate = inc.status === "triage";
  const priorSighting = inc.entities.find((e) => e.times_seen > 1);

  return (
    <>
      <Link href="/" className="back">← Queue</Link>

      <div className="inc-head">
        <div className="inc-sev" data-sev={inc.severity} />
        <div style={{ flex: 1 }}>
          <div className="inc-tags">
            <span className="mono" style={{ fontSize: "var(--text-xs)", color: "var(--paper-500)" }}>
              {inc.ref}
            </span>
            <span className="pill" data-t={inc.severity}>{inc.severity}</span>
            <span className="pill" data-t={inc.status}>{statusLabel[inc.status] ?? inc.status}</span>
            {inc.attack_technique && (
              <span className="mono" style={{ fontSize: "var(--text-xs)", color: "var(--paper-400)" }}>
                {inc.attack_technique}
              </span>
            )}
            {(canInvestigate || isInvestigating) && (
              <button
                className="btn-investigate"
                data-investigating={String(isInvestigating || investigating)}
                onClick={startInvestigation}
                disabled={isInvestigating || investigating}
              >
                {isInvestigating || investigating ? "Investigating…" : "Investigate"}
              </button>
            )}
          </div>
          <h1 className="inc-title">{inc.title}</h1>
          {inc.summary && <p className="inc-summary">{inc.summary}</p>}
          <p style={{ fontSize: "var(--text-xs)", color: "var(--paper-400)", marginTop: "var(--space-2)" }}>
            {inc.host && <span>Host: <span className="mono">{inc.host}</span> · </span>}
            {inc.primary_user && <span>User: <span className="mono">{inc.primary_user}</span> · </span>}
            <span>Opened: {fmt(inc.opened_at)}</span>
            {inc.closed_at && <span> · Closed: {fmt(inc.closed_at)}</span>}
            <span> · {inc.alert_count} alert{inc.alert_count !== 1 ? "s" : ""}</span>
          </p>
        </div>
      </div>

      {/* Memory callout — similar case or prior entity sighting */}
      {(priorSighting || inc.similar) && (
        <section className="memory">
          <div className="memory-label">Seen before</div>
          {priorSighting && (
            <p>
              <span className="mono">{priorSighting.value}</span> —{" "}
              {priorSighting.reasoning} Risk {priorSighting.risk_score}.
            </p>
          )}
          {inc.similar && (
            <p>
              Resembles <span className="mono">{inc.similar.ref}</span> —{" "}
              {inc.similar.title}. Similarity {inc.similar.similarity.toFixed(2)}.
            </p>
          )}
        </section>
      )}

      {/* Root cause (agent-written) */}
      {inc.root_cause && (
        <section className="panel">
          <p className="section-label">Root cause</p>
          <p style={{ fontSize: "var(--text-sm)", lineHeight: 1.7, margin: 0, color: "var(--paper-700)" }}>
            {inc.root_cause}
          </p>
        </section>
      )}

      {/* Hypotheses */}
      {inc.hypotheses.length > 0 && (
        <section className="panel">
          <p className="section-label">Hypotheses</p>
          {inc.hypotheses.map((h) => (
            <div key={h.id} className="hyp" data-status={h.status}>
              <div className="hyp-top">
                <span className="pill" data-t={h.status}>{h.status}</span>
                <span className="hyp-statement">{h.statement}</span>
                <span className="hyp-conf">{(h.confidence ?? 0).toFixed(2)}</span>
              </div>
              <div className="bar">
                <i style={{ width: `${Math.round((h.confidence ?? 0) * 100)}%` }} />
              </div>
              <p className="hyp-note">
                {h.supporting} supporting, {h.contradicting} contradicting
                {h.note ? ` — ${h.note}` : ""}
              </p>
            </div>
          ))}
          {awaitingAgent && !isInvestigating && (
            <p className="awaiting">
              Every hypothesis is still open — raised by the detection rules,
              not yet tested by the agent.
              {canInvestigate && " Click Investigate to start."}
            </p>
          )}
          {isInvestigating && (
            <p className="awaiting">Agent is running. Results will appear here as it works.</p>
          )}
        </section>
      )}

      {/* Evidence (agent-gathered) */}
      {inc.evidence.length > 0 && (
        <section className="panel">
          <p className="section-label">Evidence</p>
          <div className="ev-list">
            {inc.evidence.map((e) => (
              <div key={e.id} className="ev-row">
                <div className="ev-icon" data-supports={String(e.supports)} />
                <div className="ev-claim">
                  {e.claim}
                  {e.source_tool && (
                    <span className="ev-source"> · {e.source_tool}</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Timeline */}
      {inc.timeline.length > 0 && (
        <section className="panel canvas">
          <p className="section-label">Derived timeline</p>
          <div className="tl">
            {inc.timeline.map((t) => (
              <div key={t.seq} className="tl-row">
                <span className="tl-at">{fmt(t.occurred_at).slice(11, 19)}</span>
                <span className="tl-body">{t.action}</span>
                {t.attack_technique && (
                  <span className="tl-tech">{t.attack_technique}</span>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Entity memory */}
      <section className="panel">
        <p className="section-label">Entity memory</p>
        {inc.entities.length > 0 ? (
          inc.entities.map((e) => (
            <div key={e.value} className="ent">
              <div className="ent-top">
                <span className="ent-val">{e.value}</span>
                <span className="pill" data-t={e.verdict}>{e.verdict}</span>
                <span className="mono" style={{ fontSize: "var(--text-2xs)", color: "var(--paper-400)" }}>
                  {e.kind}
                </span>
              </div>
              {e.reasoning && <p className="ent-why">{e.reasoning}</p>}
              <p className="ent-stats">
                Seen {e.times_seen}× · first {e.first_seen} · risk {e.risk_score ?? "—"}
                {e.cleared_count > 0 ? ` · cleared ${e.cleared_count}×` : ""}
              </p>
            </div>
          ))
        ) : (
          <p className="awaiting">
            Nothing recalled yet. Entity memory fills as the agent investigates
            — including cleared entities, so a false positive stays cleared
            across every future investigation that touches it.
          </p>
        )}
      </section>

      {/* Full report */}
      {inc.report && (
        <section className="panel">
          <p className="section-label">Investigation report</p>
          <div className="report">{inc.report}</div>
        </section>
      )}
    </>
  );
}
