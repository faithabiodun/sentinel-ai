-- Sentinel AI — agentic memory schema
--
-- Eight tables. The design goal is that an analyst (or a judge) can read this
-- file and understand exactly what the agent remembers and why.
--
-- Requires CockroachDB v25.2+ for native VECTOR columns and vector indexes.

-- ---------------------------------------------------------------------------
-- Enums
-- ---------------------------------------------------------------------------

CREATE TYPE severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');

CREATE TYPE incident_status AS ENUM (
  'triage',        -- agent has correlated alerts, not yet investigating
  'investigating', -- agent is actively running its loop
  'contained',     -- remediation applied
  'closed',        -- resolved, root cause recorded
  'false_positive' -- cleared; the reason lands in entity_memory
);

CREATE TYPE hypothesis_status AS ENUM ('open', 'confirmed', 'refuted');

CREATE TYPE entity_kind AS ENUM ('ip', 'domain', 'hash', 'user', 'host', 'process');

-- The whole differentiator is that 'benign' exists here. Every security tool
-- remembers what was malicious; almost none remember what was *cleared and why*,
-- which is why analysts re-investigate the same false positive forever.
CREATE TYPE verdict AS ENUM ('malicious', 'suspicious', 'benign', 'unknown');

CREATE TYPE run_state AS ENUM (
  'planned',
  'intent_logged',  -- compensation committed, side effect not yet confirmed
  'succeeded',
  'failed',
  'compensated',
  'unrecoverable'
);

-- ---------------------------------------------------------------------------
-- alert — raw signal, one row per telemetry event the detectors flagged
-- ---------------------------------------------------------------------------

CREATE TABLE alert (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source        STRING NOT NULL,            -- 'sysmon', 'security', 'powershell'
  event_id      INT,                        -- Windows event ID, when applicable
  rule          STRING,                     -- detector that fired
  summary       STRING,                     -- human-readable one-liner from the detector
  raw           JSONB NOT NULL,             -- original event, unmodified
  host          STRING,
  user_principal STRING,
  observed_at   TIMESTAMPTZ NOT NULL,
  ingested_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  incident_id   UUID,                       -- set when correlated into a case

  INDEX idx_alert_incident (incident_id),
  INDEX idx_alert_observed (observed_at DESC),
  INDEX idx_alert_host_time (host, observed_at DESC)
);

-- ---------------------------------------------------------------------------
-- incident — the case. One per correlated cluster of alerts.
-- ---------------------------------------------------------------------------

CREATE TABLE incident (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ref          STRING NOT NULL,             -- human-readable INC-NNNN
  title        STRING NOT NULL,
  severity     severity NOT NULL DEFAULT 'medium',
  status       incident_status NOT NULL DEFAULT 'triage',
  host         STRING,                      -- primary host (from the alert cluster)
  primary_user STRING,                      -- principal user seen across alerts
  summary      STRING,                      -- agent-written, updated as it learns
  root_cause   STRING,
  report       STRING,                      -- full markdown report the agent writes
  attack_technique STRING,                  -- MITRE ATT&CK id, e.g. 'T1003.001'

  -- Semantic fingerprint of the case. This is what powers
  -- "this resembles Incident #17" across the historical archive.
  embedding    VECTOR(1024),

  opened_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  closed_at    TIMESTAMPTZ,

  UNIQUE INDEX idx_incident_ref (ref),
  INDEX idx_incident_status (status, opened_at DESC),
  INDEX idx_incident_severity (severity, opened_at DESC)
);

CREATE VECTOR INDEX idx_incident_embedding ON incident (embedding);

ALTER TABLE alert ADD CONSTRAINT fk_alert_incident
  FOREIGN KEY (incident_id) REFERENCES incident(id) ON DELETE SET NULL;

-- ---------------------------------------------------------------------------
-- hypothesis — the agent's structured belief.
--
-- This is what makes Sentinel agentic rather than a log summarizer. It is not
-- chat history: each row is a falsifiable claim the agent chose to test, and
-- the open -> confirmed|refuted transition is the investigation itself.
-- It is also what transfers on analyst handoff — "what was already ruled out".
-- ---------------------------------------------------------------------------

CREATE TABLE hypothesis (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id UUID NOT NULL REFERENCES incident(id) ON DELETE CASCADE,
  statement   STRING NOT NULL,              -- "credentials were dumped via LSASS access"
  rationale   STRING,                       -- why the agent thought this was worth testing
  status      hypothesis_status NOT NULL DEFAULT 'open',
  confidence  DECIMAL(4,3),                 -- 0.000–1.000, agent's own estimate
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at TIMESTAMPTZ,

  INDEX idx_hypothesis_incident (incident_id, status)
);

-- ---------------------------------------------------------------------------
-- evidence — facts gathered, each tied to what it supports or contradicts
-- ---------------------------------------------------------------------------

CREATE TABLE evidence (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id   UUID NOT NULL REFERENCES incident(id) ON DELETE CASCADE,
  hypothesis_id UUID REFERENCES hypothesis(id) ON DELETE CASCADE,
  claim         STRING NOT NULL,
  supports      BOOL NOT NULL,              -- false = this refutes the hypothesis
  source_alert_id UUID REFERENCES alert(id) ON DELETE SET NULL,
  source_tool   STRING,                     -- if gathered by a tool rather than a log
  observed_at   TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

  INDEX idx_evidence_incident (incident_id),
  INDEX idx_evidence_hypothesis (hypothesis_id)
);

-- ---------------------------------------------------------------------------
-- timeline_event — the derived attack narrative
--
-- Derived from correlated alerts, never hand-authored. If this table can only
-- be populated by hand, the demo is fake and the submission is dead.
-- ---------------------------------------------------------------------------

CREATE TABLE timeline_event (
  incident_id     UUID NOT NULL REFERENCES incident(id) ON DELETE CASCADE,
  seq             INT NOT NULL,
  occurred_at     TIMESTAMPTZ NOT NULL,
  actor           STRING,                   -- user or process responsible
  action          STRING NOT NULL,          -- "launched powershell.exe"
  detail          STRING,
  attack_technique STRING,                  -- ATT&CK id for this step
  source_alert_id UUID REFERENCES alert(id) ON DELETE SET NULL,

  PRIMARY KEY (incident_id, seq)
);

-- ---------------------------------------------------------------------------
-- tool_run — every action the agent took, with its undo written first
--
-- Protocol, in order:
--   1. TX: INSERT with compensation populated, state = 'intent_logged'  COMMIT
--   2.     execute the side effect, passing idempotency_key
--   3. TX: UPDATE state = 'succeeded', result = ...                     COMMIT
--
-- A crash between 1 and 3 leaves 'intent_logged', which means "we do not know
-- whether this happened". Recovery reconciles by idempotency key, and failing
-- that runs the compensation, which must itself be idempotent. This matters
-- because containment actions are destructive: isolating the wrong host is a
-- real outage.
-- ---------------------------------------------------------------------------

CREATE TABLE tool_run (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id     UUID NOT NULL REFERENCES incident(id) ON DELETE CASCADE,
  seq             INT NOT NULL,
  tool            STRING NOT NULL,
  args            JSONB NOT NULL,
  idempotency_key STRING NOT NULL UNIQUE,
  compensation    JSONB,                    -- {tool, args} — committed BEFORE execute
  destructive     BOOL NOT NULL DEFAULT false,
  state           run_state NOT NULL DEFAULT 'planned',
  result          JSONB,
  attempts        INT NOT NULL DEFAULT 0,
  started_at      TIMESTAMPTZ,
  finished_at     TIMESTAMPTZ,

  UNIQUE (incident_id, seq),
  INDEX idx_toolrun_state (state) WHERE state = 'intent_logged'
);

-- ---------------------------------------------------------------------------
-- entity_memory — knowledge that outlives any single incident
--
-- This is the long-term memory. An IP, hash, user or host accumulates a verdict
-- and a sighting history across every investigation that ever touched it, so
-- month two starts from what month one learned.
-- ---------------------------------------------------------------------------

CREATE TABLE entity_memory (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind         entity_kind NOT NULL,
  value        STRING NOT NULL,
  verdict      verdict NOT NULL DEFAULT 'unknown',

  -- Why the agent reached this verdict, in prose. For 'benign' this is the
  -- payload that stops the same false positive being re-investigated forever:
  -- "matches the nightly backup job, cleared in INC-0031, confirmed by ops."
  reasoning    STRING,

  risk_score   INT,                         -- 0–100
  first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
  times_seen   INT NOT NULL DEFAULT 1,
  cleared_count INT NOT NULL DEFAULT 0,     -- how often this was ruled benign
  embedding    VECTOR(1024),                -- fuzzy recall over reasoning text

  UNIQUE (kind, value),
  INDEX idx_entity_verdict (verdict, risk_score DESC)
);

CREATE VECTOR INDEX idx_entity_embedding ON entity_memory (embedding);

-- Join table: which incidents has this entity appeared in. Powers
-- "previously seen: YES, first seen January, associated with credential stuffing".
CREATE TABLE entity_sighting (
  entity_id   UUID NOT NULL REFERENCES entity_memory(id) ON DELETE CASCADE,
  incident_id UUID NOT NULL REFERENCES incident(id) ON DELETE CASCADE,
  seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

  PRIMARY KEY (entity_id, incident_id)
);

-- ---------------------------------------------------------------------------
-- analyst — human users of the platform
-- ---------------------------------------------------------------------------

CREATE TABLE analyst (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         STRING NOT NULL,
  display_name  STRING NOT NULL,
  password_hash STRING NOT NULL,
  role          STRING NOT NULL DEFAULT 'analyst',  -- 'analyst' | 'admin'
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login    TIMESTAMPTZ,

  UNIQUE INDEX idx_analyst_email (email)
);
