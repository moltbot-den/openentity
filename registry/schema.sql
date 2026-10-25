-- Open Entity registry, PostgreSQL 16 schema (PRD section 8).
-- Every statement is idempotent. Statements are separated by semicolons at line ends.

CREATE TABLE IF NOT EXISTS entities (
  eid TEXT PRIMARY KEY,
  root_method TEXT NOT NULL,
  name TEXT NOT NULL,
  level BIGINT,                -- 0..3, NULL when withdrawn
  level_label TEXT,             -- 'first-party' or 'independent' for L2 and L3
  created TEXT NOT NULL,
  updated TEXT NOT NULL,        -- time of the latest signed write (dormancy)
  withdrawn_at TEXT,
  suppressed BIGINT NOT NULL DEFAULT 0,
  custody TEXT,
  latest_seq BIGINT NOT NULL,  -- Entity Document seq
  record_seq BIGINT NOT NULL DEFAULT 0,
  record_head_hash TEXT,
  predecessor_eid TEXT,
  successor_eid TEXT,
  founding BIGINT NOT NULL DEFAULT 0,
  adopted_log_index BIGINT
);
CREATE INDEX IF NOT EXISTS entities_level ON entities(level, created);

CREATE TABLE IF NOT EXISTS documents (
  eid TEXT NOT NULL, seq BIGINT NOT NULL, json TEXT NOT NULL, sha256 TEXT NOT NULL,
  received_at TEXT NOT NULL, log_index BIGINT,
  PRIMARY KEY (eid, seq)
);

CREATE TABLE IF NOT EXISTS declarations (
  eid TEXT NOT NULL, version TEXT NOT NULL, json TEXT NOT NULL, sha256 TEXT NOT NULL,
  received_at TEXT NOT NULL, log_index BIGINT, withdrawn_at TEXT, withdrawal_json TEXT,
  PRIMARY KEY (eid, version)
);

CREATE TABLE IF NOT EXISTS aliases (
  eid TEXT NOT NULL, type TEXT NOT NULL, value TEXT NOT NULL, proof_json TEXT,
  verified_at TEXT, last_checked TEXT, status TEXT NOT NULL, log_index BIGINT,
  PRIMARY KEY (eid, type, value)
);
CREATE INDEX IF NOT EXISTS aliases_reverse ON aliases(type, value);

CREATE TABLE IF NOT EXISTS record_entries (
  eid TEXT NOT NULL, seq BIGINT NOT NULL, kind TEXT NOT NULL, json TEXT NOT NULL, sha256 TEXT NOT NULL,
  received_at TEXT NOT NULL, log_index BIGINT,
  PRIMARY KEY (eid, seq)
);

CREATE TABLE IF NOT EXISTS attestations (
  sha256 TEXT PRIMARY KEY, issuer TEXT NOT NULL, subject TEXT NOT NULL, claim_type TEXT NOT NULL,
  json TEXT NOT NULL, created TEXT NOT NULL, expires TEXT NOT NULL,
  revoked_at TEXT, revocation_json TEXT, log_index BIGINT
);
CREATE INDEX IF NOT EXISTS attestations_subject ON attestations(subject, claim_type);
CREATE INDEX IF NOT EXISTS attestations_issuer ON attestations(issuer);

CREATE TABLE IF NOT EXISTS continuity_links (
  sha256 TEXT PRIMARY KEY, previous TEXT NOT NULL, successor TEXT NOT NULL, basis TEXT NOT NULL,
  json TEXT NOT NULL, received_at TEXT NOT NULL, log_index BIGINT
);
CREATE UNIQUE INDEX IF NOT EXISTS continuity_one_predecessor ON continuity_links(successor);

-- The next free log index. Only the sequencer (log.ts) moves it, in the same statement that moves pending
-- leaves into log_leaves, so the index stays contiguous and gap-free.
CREATE TABLE IF NOT EXISTS log_head (
  id BIGINT PRIMARY KEY CHECK (id = 1), next BIGINT NOT NULL
);
INSERT INTO log_head (id, next) VALUES (1, 0) ON CONFLICT DO NOTHING;

-- Group commit: a write inserts its object rows and its leaves here in one statement, without touching
-- log_head. Its rows carry the placeholder log index -(wid * 1024) + o (negative) until the sequencer
-- moves the leaves into log_leaves and rewrites the placeholders.
CREATE TABLE IF NOT EXISTS log_pending (
  seq BIGSERIAL PRIMARY KEY, wid BIGINT NOT NULL, o INT NOT NULL, leaf_hash TEXT NOT NULL, type TEXT NOT NULL,
  eid TEXT NOT NULL, object_sha256 TEXT NOT NULL, received_at TEXT NOT NULL
);

-- Leaf indexes are assigned by the sequencer; the cron incorporates them. wid ties a leaf to its write.
CREATE TABLE IF NOT EXISTS log_leaves (
  idx BIGINT PRIMARY KEY, leaf_hash TEXT NOT NULL, type TEXT NOT NULL, eid TEXT NOT NULL,
  object_sha256 TEXT NOT NULL, received_at TEXT NOT NULL
);
ALTER TABLE log_leaves ADD COLUMN IF NOT EXISTS wid BIGINT;
CREATE INDEX IF NOT EXISTS log_leaves_received ON log_leaves(received_at);
CREATE INDEX IF NOT EXISTS log_leaves_wid ON log_leaves(wid);

-- Hash of the complete subtree of 2^level leaves starting at leaf idx * 2^level.
CREATE TABLE IF NOT EXISTS log_nodes (
  level BIGINT NOT NULL, idx BIGINT NOT NULL, hash TEXT NOT NULL,
  PRIMARY KEY (level, idx)
);

CREATE TABLE IF NOT EXISTS checkpoints (
  tree_size BIGINT PRIMARY KEY, root_hash TEXT NOT NULL, timestamp TEXT NOT NULL, signed_note TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observers (
  did TEXT PRIMARY KEY, name TEXT, trust_policy_url TEXT, methodology_url TEXT, level BIGINT,
  accredited_at TEXT NOT NULL, bootstrap BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS stats_daily (
  date TEXT PRIMARY KEY, entities_l0 BIGINT, entities_l1 BIGINT, entities_l2 BIGINT, entities_l3 BIGINT,
  adoptions BIGINT, record_entries BIGINT, attestations BIGINT, observers BIGINT
);

-- Hashed keys only (IPs, emails, stamps). Per-minute and per-day counters. Swept by the scheduled handler.
CREATE TABLE IF NOT EXISTS rate_events (
  key TEXT NOT NULL, window_start TEXT NOT NULL, count BIGINT NOT NULL,
  PRIMARY KEY (key, window_start)
);

-- Custodial mode (spec 10.6): AES-GCM encrypted with the CUSTODY_KEY secret.
CREATE TABLE IF NOT EXISTS custodial_keys (
  eid TEXT PRIMARY KEY, enc_key TEXT NOT NULL, created TEXT NOT NULL
);

-- Self-declared capabilities from the latest Entity Document (spec 5.2), for directory search.
CREATE TABLE IF NOT EXISTS entity_capabilities (
  eid TEXT NOT NULL,
  capability TEXT NOT NULL,
  PRIMARY KEY (eid, capability)
);
CREATE INDEX IF NOT EXISTS entity_capabilities_by_capability ON entity_capabilities (capability);

-- Signed disputes (spec 10.5): against an entity, or one of its objects by SHA-256. Answered within 14 days.
CREATE TABLE IF NOT EXISTS disputes (
  sha256 TEXT PRIMARY KEY,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  object_sha256 TEXT,
  reason TEXT NOT NULL,
  json TEXT NOT NULL,
  received_at TEXT NOT NULL,
  log_index BIGINT
);
CREATE INDEX IF NOT EXISTS disputes_by_subject ON disputes (subject);
CREATE INDEX IF NOT EXISTS disputes_by_object ON disputes (object_sha256);

-- Placeholder log indexes (negative) exist only between a write and its sequencing; these tiny indexes let the sequencer find them.
CREATE INDEX IF NOT EXISTS declarations_pending ON declarations(log_index) WHERE log_index < 0;
CREATE INDEX IF NOT EXISTS documents_pending ON documents(log_index) WHERE log_index < 0;
CREATE INDEX IF NOT EXISTS entities_pending ON entities(adopted_log_index) WHERE adopted_log_index < 0;
CREATE INDEX IF NOT EXISTS aliases_pending ON aliases(log_index) WHERE log_index < 0;
CREATE INDEX IF NOT EXISTS record_entries_pending ON record_entries(log_index) WHERE log_index < 0;
CREATE INDEX IF NOT EXISTS attestations_pending ON attestations(log_index) WHERE log_index < 0;
CREATE INDEX IF NOT EXISTS continuity_links_pending ON continuity_links(log_index) WHERE log_index < 0;
CREATE INDEX IF NOT EXISTS disputes_pending ON disputes(log_index) WHERE log_index < 0;
