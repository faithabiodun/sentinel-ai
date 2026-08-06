export default function AboutPage() {
  return (
    <>
      <div className="page-head">
        <h1 className="page-title">About</h1>
        <p className="page-sub">
          An agentic security incident investigator, built for the CockroachDB × AWS
          hackathon.
        </p>
      </div>

      <section className="panel">
        <p className="section-label">What it remembers</p>
        <p style={{ fontSize: "var(--text-sm)", lineHeight: 1.7, margin: "0 0 var(--space-3)" }}>
          Detection is largely solved. Institutional memory is not. The same address gets
          looked up for the fourth time; the same PowerShell pattern gets escalated again,
          months after someone established it was the nightly backup job.
        </p>
        <p style={{ fontSize: "var(--text-sm)", lineHeight: 1.7, margin: 0 }}>
          Sentinel keeps four kinds of memory as first-class tables rather than a
          serialised blob: structured belief, gathered evidence, long-term entity
          knowledge, and a semantic fingerprint of every case it has closed.
        </p>
      </section>

      <section className="panel">
        <p className="section-label">Stack</p>
        <p style={{ fontSize: "var(--text-sm)", lineHeight: 1.8, margin: 0, color: "var(--paper-600)" }}>
          CockroachDB — memory, vector recall, MCP server
          <br />
          Amazon Bedrock — planning and embeddings
          <br />
          Amazon S3 — raw telemetry and reports
          <br />
          Railway — hosting
        </p>
      </section>

      <p className="empty">Running on sample data. Memory layer not yet connected.</p>
    </>
  );
}
