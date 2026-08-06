import Link from "next/link";
import { incidents, queueStats } from "@/lib/mock";

const statusLabel: Record<string, string> = {
  triage: "triage",
  investigating: "investigating",
  contained: "contained",
  closed: "closed",
  false_positive: "auto-cleared",
};

export default function QueuePage() {
  return (
    <>
      <div className="page-head">
        <h1 className="page-title">Triage queue</h1>
        <p className="page-sub">
          Ordered by severity, then by what the agent has not yet ruled out.
        </p>
      </div>

      <div className="counters">
        <div>
          <div className="counter-n">{queueStats.open}</div>
          <div className="counter-l">Open</div>
        </div>
        <div>
          <div className="counter-n" data-tone="cleared">
            {queueStats.autoCleared}
          </div>
          <div className="counter-l">Auto-cleared</div>
        </div>
        <div>
          <div className="counter-n">{queueStats.entitiesKnown.toLocaleString()}</div>
          <div className="counter-l">Entities known</div>
        </div>
      </div>

      <div className="queue-head">
        <span>Ref</span>
        <span>Incident</span>
        <span>Host</span>
        <span>Technique</span>
        <span>Status</span>
        <span>Opened</span>
      </div>

      <div className="queue">
        {incidents.map((inc) => (
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
              <span className="mono">{inc.host}</span>
              <span className="mono">{inc.technique ?? "—"}</span>
              <span className="pill" data-t={inc.status}>
                {statusLabel[inc.status] ?? inc.status}
              </span>
              <span className="row-time">{inc.openedAt}</span>
            </div>
          </Link>
        ))}
      </div>
    </>
  );
}
