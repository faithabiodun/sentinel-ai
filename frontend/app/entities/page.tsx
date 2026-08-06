import { knownEntities, provenance } from "@/lib/data";

export default function EntitiesPage() {
  const cleared = knownEntities.filter((e) => e.verdict === "benign").length;

  return (
    <>
      <div className="page-head">
        <h1 className="page-title">Memory</h1>
        <p className="page-sub">
          What the agent knows about entities it has seen before — including the
          ones it has already cleared.
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
          <div className="counter-n">{provenance.incidents}</div>
          <div className="counter-l">Incidents seen</div>
        </div>
      </div>

      {knownEntities.length === 0 ? (
        <section className="panel">
          <p className="awaiting" style={{ margin: 0 }}>
            Empty, and honestly so. This is where an address, hash, user or host
            accumulates a verdict across every investigation that ever touched
            it — including <strong>benign</strong>, with the reasoning attached,
            so a cleared false positive stays cleared.
            <br />
            <br />
            It fills up once the CockroachDB memory layer is connected and the
            agent has run. Showing invented entries here would defeat the point
            of the feature.
          </p>
        </section>
      ) : (
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
      )}
    </>
  );
}
