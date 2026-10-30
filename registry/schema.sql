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
-- Optional unsigned label sent with POST /adopt (allowlist in index.ts); counted by GET /stats as by_client.
ALTER TABLE entities ADD COLUMN IF NOT EXISTS client TEXT;
-- The Withdrawal signed by a successor that withdrew an inherited Declaration (spec 9.3); own-Declaration withdrawals live on declarations.
ALTER TABLE entities ADD COLUMN IF NOT EXISTS withdrawal_json TEXT;

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

-- Time-to-adopt funnel (PRD 12). Seconds from the first GET /llms.txt to the adopt from the same hashed address; no address is stored
-- (the start lives in rate_events as key fs:<salted hash>, count = epoch seconds, 24 h life). internal = operated by Moltbot Den.
CREATE TABLE IF NOT EXISTS adopt_funnel (
  eid TEXT PRIMARY KEY, seconds BIGINT NOT NULL, internal BIGINT NOT NULL DEFAULT 0
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

-- Group commit, step 2 (log.ts `sequence`): give write w's leaves, and every other pending leaf, their log indexes.
-- Returns w's first index once it is in the log, or NULL when another sequencer holds log_head (the caller polls).
-- A function, not one statement, so the common path (already moved, or sequencer busy) plans and locks only the
-- two tiny statements it runs; planning the full statement on every poll saturated a 4 ACU writer.
-- READ COMMITTED: each statement below takes a fresh snapshot. The move runs only after this transaction holds
-- the log_head row lock, which the previous sequencer released by committing, so its snapshot sees every leaf
-- that sequencer moved (none is moved twice) and every write parked before it (w's own included). Only one
-- sequencer runs at a time and SKIP LOCKED keeps the others from queueing on the row, so there is no convoy.
-- The move is one statement: delete the pending leaves, take their indexes from log_head in one bump, insert
-- them into log_leaves in write order (a write's leaves stay consecutive), replace the placeholder indexes.
CREATE OR REPLACE FUNCTION log_sequence(w BIGINT) RETURNS BIGINT LANGUAGE plpgsql AS $$
DECLARE i BIGINT;
BEGIN
  SELECT min(idx) INTO i FROM log_leaves WHERE wid = w;
  IF i IS NOT NULL THEN RETURN i; END IF;
  PERFORM 1 FROM log_head WHERE id = 1 FOR UPDATE SKIP LOCKED;
  IF NOT FOUND THEN RETURN NULL; END IF;
  WITH mv AS (DELETE FROM log_pending RETURNING *),
  c AS (SELECT count(*) AS k FROM mv),
  h AS (UPDATE log_head SET next = next + (SELECT k FROM c) WHERE id = 1 AND (SELECT k FROM c) > 0 RETURNING next - (SELECT k FROM c) AS b),
  n AS (SELECT m.*, h.b + row_number() OVER (ORDER BY m.g, m.o) - 1 AS idx FROM (SELECT mv.*, min(seq) OVER (PARTITION BY mv.wid) AS g FROM mv) m, h),
  l AS (INSERT INTO log_leaves (idx, leaf_hash, type, eid, object_sha256, received_at, wid) SELECT n.idx, n.leaf_hash, n.type, n.eid, n.object_sha256, n.received_at, n.wid FROM n),
  u0 AS (UPDATE declarations t SET log_index = n.idx FROM n WHERE t.log_index < 0 AND t.log_index = -n.wid * 1024 + n.o),
  u1 AS (UPDATE documents t SET log_index = n.idx FROM n WHERE t.log_index < 0 AND t.log_index = -n.wid * 1024 + n.o),
  u2 AS (UPDATE entities t SET adopted_log_index = n.idx FROM n WHERE t.adopted_log_index < 0 AND t.adopted_log_index = -n.wid * 1024 + n.o),
  u3 AS (UPDATE aliases t SET log_index = n.idx FROM n WHERE t.log_index < 0 AND t.log_index = -n.wid * 1024 + n.o),
  u4 AS (UPDATE record_entries t SET log_index = n.idx FROM n WHERE t.log_index < 0 AND t.log_index = -n.wid * 1024 + n.o),
  u5 AS (UPDATE attestations t SET log_index = n.idx FROM n WHERE t.log_index < 0 AND t.log_index = -n.wid * 1024 + n.o),
  u6 AS (UPDATE continuity_links t SET log_index = n.idx FROM n WHERE t.log_index < 0 AND t.log_index = -n.wid * 1024 + n.o),
  u7 AS (UPDATE disputes t SET log_index = n.idx FROM n WHERE t.log_index < 0 AND t.log_index = -n.wid * 1024 + n.o)
  SELECT min(n.idx) INTO i FROM n WHERE n.wid = w;
  RETURN i;
END $$;

-- Lookups by object hash (log inclusion, dispute and withdrawal paths) must not scan.
CREATE INDEX IF NOT EXISTS log_leaves_object ON log_leaves(object_sha256);
CREATE INDEX IF NOT EXISTS documents_sha256 ON documents(sha256);
CREATE INDEX IF NOT EXISTS declarations_sha256 ON declarations(sha256);
CREATE INDEX IF NOT EXISTS record_entries_sha256 ON record_entries(sha256);
CREATE INDEX IF NOT EXISTS continuity_links_sha256 ON continuity_links(sha256);
