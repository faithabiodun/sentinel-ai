# Sentinel AI

An agentic security incident investigator. It works a queue of alerts the way a
Tier 1/2 SOC analyst does — correlates them into cases, forms hypotheses, gathers
evidence to confirm or refute them, derives an attack timeline, recommends
containment, and writes the report.

The part that matters is what it remembers between cases.

Built for the CockroachDB × AWS Hackathon — *Build with Agentic Memory*.

## The problem

A SOC analyst's day is mostly re-derivation. The same IP gets looked up for the
fourth time. The same PowerShell pattern gets escalated again, three months after
someone established it was the nightly backup job — but that finding lived in a
Slack thread and the analyst who wrote it has left.

Detection is largely solved. **Institutional memory is not.**

## What Sentinel remembers

Four kinds of memory, each a first-class table rather than a serialised blob:

| Memory | Table | What it buys |
|---|---|---|
| Structured belief | `hypothesis` | An investigation is a set of falsifiable claims moving from `open` to `confirmed`/`refuted`. Hand it to another analyst and they know what was already ruled out. |
| Gathered fact | `evidence` | Every claim tied to the alert or tool call that produced it, and whether it supports or *contradicts* the hypothesis. |
| Long-term entity knowledge | `entity_memory` | An IP, hash, user or host carries its verdict and sighting history across every case that ever touched it. |
| Case fingerprint | `incident.embedding` | "This resembles INC-0017" — semantic recall over the whole historical archive via CockroachDB vector indexing. |

### The bit nobody else builds

Every security tool remembers what was **malicious**. Sentinel also remembers what
was **cleared, and why**:

```
entity_memory
  kind:          process
  value:         powershell.exe -enc <backup routine>
  verdict:       benign
  reasoning:     matches nightly backup job; cleared in INC-0031,
                 confirmed by ops on 2026-03-04
  cleared_count: 4
```

An agent that stops raising a question you have already answered four times is
worth more than one that raises it faster.

## Architecture

```
Windows Sysmon/EVTX  ──▶  detectors  ──▶  incident correlation
                                                  │
                                                  ▼
                                          agent loop (LangGraph)
                                          plan → hypothesis → tool → evidence
                                                  │
       ┌──────────────────────────────────────────┼───────────────────────┐
       ▼                                          ▼                       ▼
  CockroachDB                             Amazon Bedrock              Amazon S3
  memory + vector recall                  planning + embeddings       raw logs, reports
  MCP Server for agent access
```

| Layer | Choice |
|---|---|
| Memory | CockroachDB Cloud — native vector indexing, MCP Server, provisioned via `ccloud` |
| Reasoning | Claude on Amazon Bedrock |
| Embeddings | Amazon Titan Text Embeddings v2 (1024-dim) |
| Object storage | Amazon S3 |
| Backend | FastAPI |
| Frontend | Next.js |
| Hosting | Railway |

Agent execution state is checkpointed to CockroachDB, so an investigation
survives a process restart and resumes rather than starting over.

### Destructive actions carry their own undo

Containment steps — isolate host, disable account, block IP — commit a
compensating action to `tool_run` *before* they execute. A crash mid-action
leaves `state = 'intent_logged'`, which recovery treats as "we do not know
whether this happened" and reconciles by idempotency key.

Isolating the wrong host is a real outage. The undo is not optional.

## Data

Sentinel is developed against **real attack telemetry, not hand-authored samples**
— public Sysmon/EVTX captures from executed attack techniques, where ground truth
is known independently. That makes the derived timelines checkable and lets the
project report precision, recall, and mean-time-to-triage rather than asserting
that it works.

## Running it

```bash
python -m venv .venv && .venv/Scripts/activate     # source .venv/bin/activate elsewhere
pip install -r backend/requirements.txt

python scripts/fetch_datasets.py   # pull the attack corpus
python scripts/evaluate.py         # score detectors against shipped labels
python scripts/triage.py           # full pipeline: events -> alerts -> incidents
```

Current numbers, reproducible from a clean checkout:

```
ground-truth technique recovered: 8/8 (100%)
75 events -> 17 alerts -> 7 incidents
rules exercised: 9/9
```

### Connecting the memory layer

```bash
cp .env.example .env          # fill in DATABASE_URL, AWS credentials, JWT_SECRET

python scripts/migrate.py     # apply db/schema.sql to CockroachDB
python scripts/load_db.py     # persist pipeline output (incidents, alerts, hypotheses)

# Backend API
uvicorn backend.app.main:app --reload --port 8000

# Frontend (separate terminal)
cd frontend && npm install && npm run dev
```

The frontend is now behind auth — create an account at `/signup`, then open
an incident and click **Investigate** to run the agent loop.

## Status

Fully built end-to-end:

| Layer | Status |
|---|---|
| Ingestion & detection | ✓ working, 8/8 techniques recovered |
| Correlation | ✓ working |
| Schema & migration | ✓ `scripts/migrate.py` |
| DB loader | ✓ `scripts/load_db.py` |
| FastAPI backend | ✓ auth, incidents, entities, investigate |
| Agent loop | ✓ Claude on Bedrock + tool dispatch |
| Entity memory | ✓ upsert with benign-cleared tracking |
| Vector similarity | ✓ incident embedding via Titan |
| Auth (JWT) | ✓ sign-up / sign-in / protected routes |
| Frontend | ✓ live API, middleware-gated, investigate button |

Needs: CockroachDB Cloud cluster + AWS Bedrock access to run the agent.

## Licence

Apache 2.0.
