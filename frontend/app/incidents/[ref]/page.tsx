import Link from "next/link";
import { notFound } from "next/navigation";
import { getIncident, incidents } from "@/lib/data";

export function generateStaticParams() {
  return incidents.map((i) => ({ ref: i.ref }));
}

const statusLabel: Record<string, string> = {
  triage: "triage",
  investigating: "investigating",
  contained: "contained",
  closed: "closed",
  false_positive: "auto-cleared",
};

export default async function IncidentPage({ params }: PageProps<"/incidents/[ref]">) {
  const { ref } = await params;
  const inc = getIncident(ref);
  if (!inc) notFound();

  const priorSighting = inc.entities.find((e) => e.timesSeen > 1);
  const awaitingAgent = inc.hypotheses.every((h) => h.status === "open");

  return (
    <>
      <Link href="/" className="back">
        ← Queue
      </Link>

      <div className="inc-head">
        <div className="inc-sev" data-sev={inc.severity} />
        <div>
          <div className="inc-tags">
            <span
              className="mono"
              style={{ fontSize: "var(--text-xs)", color: "var(--paper-500)" }}
            >
              {inc.ref}
            </span>
            <span className="pill" data-t={inc.severity}>
              {inc.severity}
            </span>
            <span className="pill" data-t={inc.status}>
              {statusLabel[inc.status] ?? inc.status}
            </span>
            {inc.technique && (
              <span
                className="mono"
                style={{ fontSize: "var(--text-xs)", color: "var(--paper-400)" }}
              >
                {inc.technique}
              </span>
            )}
          </div>
          <h1 className="inc-title">{inc.title}</h1>
          {inc.summary && <p className="inc-summary">{inc.summary}</p>}
        </div>
      </div>

      {(priorSighting || inc.resembles) && (
        <section className="memory">
          <div className="memory-label">Seen before</div>
          {priorSighting && (
            <p>
              <span className="mono">{priorSighting.value}</span> —{" "}
              {priorSighting.reasoning} Risk {priorSighting.riskScore}.
            </p>
          )}
          {inc.resembles && (
            <p>
              Resembles <span className="mono">{inc.resembles.ref}</span> —{" "}
              {inc.resembles.why}. Similarity {inc.resembles.similarity.toFixed(2)}.
            </p>
          )}
        </section>
      )}

      {inc.hypotheses.length > 0 && (
        <section className="panel">
          <p className="section-label">Hypotheses</p>
          {inc.hypotheses.map((h) => (
            <div key={h.id} className="hyp" data-status={h.status}>
              <div className="hyp-top">
                <span className="pill" data-t={h.status}>
                  {h.status}
                </span>
                <span className="hyp-statement">{h.statement}</span>
                <span className="hyp-conf">{h.confidence.toFixed(2)}</span>
              </div>
              <div className="bar">
                <i style={{ width: `${Math.round(h.confidence * 100)}%` }} />
              </div>
              <p className="hyp-note">
                {h.supporting} supporting, {h.contradicting} contradicting
                {h.note ? ` — ${h.note}` : ""}
              </p>
            </div>
          ))}
          {awaitingAgent && (
            <p className="awaiting">
              Every hypothesis is still open. These were raised by the detection
              rules; confirming or refuting them is the agent&apos;s job, and the
              agent is not connected yet.
            </p>
          )}
        </section>
      )}

      {inc.timeline.length > 0 && (
        <section className="panel canvas">
          <p className="section-label">Derived timeline</p>
          <div className="tl">
            {inc.timeline.map((t) => (
              <div key={t.seq} className="tl-row">
                <span className="tl-at">{t.at}</span>
                <span className="tl-body">
                  {t.action}
                  {t.occurrences > 1 && (
                    <span className="tl-count"> ×{t.occurrences}</span>
                  )}
                </span>
                {t.technique && <span className="tl-tech">{t.technique}</span>}
              </div>
            ))}
          </div>
        </section>
      )}

      {inc.entities.length > 0 ? (
        <section className="panel">
          <p className="section-label">Entity memory</p>
          {inc.entities.map((e) => (
            <div key={e.value} className="ent">
              <div className="ent-top">
                <span className="ent-val">{e.value}</span>
                <span className="pill" data-t={e.verdict}>
                  {e.verdict}
                </span>
              </div>
              <p className="ent-why">{e.reasoning}</p>
              <p className="ent-stats">
                Seen {e.timesSeen}× · first {e.firstSeen} · risk {e.riskScore}
                {e.clearedCount > 0 ? ` · cleared ${e.clearedCount}×` : ""}
              </p>
            </div>
          ))}
        </section>
      ) : (
        <section className="panel">
          <p className="section-label">Entity memory</p>
          <p className="awaiting">
            Nothing recalled. Entity memory accumulates across investigations —
            it needs the CockroachDB layer connected before this incident can be
            compared against anything that came before it.
          </p>
        </section>
      )}
    </>
  );
}
