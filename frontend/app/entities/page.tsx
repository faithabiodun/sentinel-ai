import { knownEntities } from "@/lib/mock";

export default function EntitiesPage() {
  const cleared = knownEntities.filter((e) => e.verdict === "benign").length;

  return (
    <>
      <div className="page-head">
        <h1 className="page-title">Memory</h1>
        <p className="page-sub">
          What the agent knows about entities it has seen before — including the ones it
          has already cleared.
        </p>
      </div>

      <div className="counters">
        <div>
          <div className="counter-n">{knownEntities.length}</div>
          <div className="counter-l">Tracked</div>
        </div>
        <div>
          <div className="counter-n" data-tone="cleared">
            {cleared}
          </div>
          <div className="counter-l">Known benign</div>
        </div>
        <div>
          <div className="counter-n">
            {knownEntities.reduce((n, e) => n + e.clearedCount, 0)}
          </div>
          <div className="counter-l">Re-checks avoided</div>
        </div>
      </div>

      <section className="panel">
        {knownEntities.map((e) => (
          <div key={e.value} className="ent">
            <div className="ent-top">
              <span className="ent-val">{e.value}</span>
              <span className="pill" data-t={e.verdict}>
                {e.verdict}
              </span>
              <span
                className="mono"
                style={{ fontSize: "var(--text-2xs)", color: "var(--paper-400)" }}
              >
                {e.kind}
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
    </>
  );
}
