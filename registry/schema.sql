-- Open Entity registry, D1 schema (PRD section 8). Apply with:
--   wrangler d1 execute openentity-registry --remote --file schema.sql
-- Every statement is idempotent. Statements are separated by semicolons at line ends.

CREATE TABLE IF NOT EXISTS entities (
  eid TEXT PRIMARY KEY,
  root_method TEXT NOT NULL,
  name TEXT NOT NULL,
  level INTEGER,                -- 0..3, NULL when withdrawn
  level_label TEXT,             -- 'first-party' or 'independent' for L2 and L3
  created TEXT NOT NULL,
  updated TEXT NOT NULL,        -- time of the latest signed write (dormancy)
  withdrawn_at TEXT,
  suppressed INTEGER NOT NULL DEFAULT 0,
  custody TEXT,
  latest_seq INTEGER NOT NULL,  -- Entity Document seq
  record_seq INTEGER NOT NULL DEFAULT 0,
  record_head_hash TEXT,
  predecessor_eid TEXT,
  successor_eid TEXT,
  founding INTEGER NOT NULL DEFAULT 0,
  adopted_log_index INTEGER
);
CREATE INDEX IF NOT EXISTS entities_level ON entities(level, created);

CREATE TABLE IF NOT EXISTS documents (
  eid TEXT NOT NULL, seq INTEGER NOT NULL, json TEXT NOT NULL, sha256 TEXT NOT NULL,
  received_at TEXT NOT NULL, log_index INTEGER,
  PRIMARY KEY (eid, seq)
);

CREATE TABLE IF NOT EXISTS declarations (
  eid TEXT NOT NULL, version TEXT NOT NULL, json TEXT NOT NULL, sha256 TEXT NOT NULL,
  received_at TEXT NOT NULL, log_index INTEGER, withdrawn_at TEXT, withdrawal_json TEXT,
  PRIMARY KEY (eid, version)
);

CREATE TABLE IF NOT EXISTS aliases (
  eid TEXT NOT NULL, type TEXT NOT NULL, value TEXT NOT NULL, proof_json TEXT,
  verified_at TEXT, last_checked TEXT, status TEXT NOT NULL, log_index INTEGER,
  PRIMARY KEY (eid, type, value)
);
CREATE INDEX IF NOT EXISTS aliases_reverse ON aliases(type, value);

CREATE TABLE IF NOT EXISTS record_entries (
  eid TEXT NOT NULL, seq INTEGER NOT NULL, kind TEXT NOT NULL, json TEXT NOT NULL, sha256 TEXT NOT NULL,
  received_at TEXT NOT NULL, log_index INTEGER,
  PRIMARY KEY (eid, seq)
);

CREATE TABLE IF NOT EXISTS attestations (
  sha256 TEXT PRIMARY KEY, issuer TEXT NOT NULL, subject TEXT NOT NULL, claim_type TEXT NOT NULL,
  json TEXT NOT NULL, created TEXT NOT NULL, expires TEXT NOT NULL,
  revoked_at TEXT, revocation_json TEXT, log_index INTEGER
);
CREATE INDEX IF NOT EXISTS attestations_subject ON attestations(subject, claim_type);
CREATE INDEX IF NOT EXISTS attestations_issuer ON attestations(issuer);

CREATE TABLE IF NOT EXISTS continuity_links (
  sha256 TEXT PRIMARY KEY, previous TEXT NOT NULL, successor TEXT NOT NULL, basis TEXT NOT NULL,
  json TEXT NOT NULL, received_at TEXT NOT NULL, log_index INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS continuity_one_predecessor ON continuity_links(successor);

-- Leaf indexes are assigned at write time (sequencing); the queue consumer incorporates them.
CREATE TABLE IF NOT EXISTS log_leaves (
  idx INTEGER PRIMARY KEY, leaf_hash TEXT NOT NULL, type TEXT NOT NULL, eid TEXT NOT NULL,
  object_sha256 TEXT NOT NULL, received_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS log_leaves_received ON log_leaves(received_at);

-- Hash of the complete subtree of 2^level leaves starting at leaf idx * 2^level.
CREATE TABLE IF NOT EXISTS log_nodes (
  level INTEGER NOT NULL, idx INTEGER NOT NULL, hash TEXT NOT NULL,
  PRIMARY KEY (level, idx)
);

CREATE TABLE IF NOT EXISTS checkpoints (
  tree_size INTEGER PRIMARY KEY, root_hash TEXT NOT NULL, timestamp TEXT NOT NULL, signed_note TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observers (
  did TEXT PRIMARY KEY, name TEXT, trust_policy_url TEXT, methodology_url TEXT, level INTEGER,
  accredited_at TEXT NOT NULL, bootstrap INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS stats_daily (
  date TEXT PRIMARY KEY, entities_l0 INTEGER, entities_l1 INTEGER, entities_l2 INTEGER, entities_l3 INTEGER,
  adoptions INTEGER, record_entries INTEGER, attestations INTEGER, observers INTEGER
);

-- Hashed keys only (IPs, emails, stamps). Swept by the scheduled handler.
CREATE TABLE IF NOT EXISTS rate_events (
  key TEXT NOT NULL, window_start TEXT NOT NULL, count INTEGER NOT NULL,
  PRIMARY KEY (key, window_start)
);

-- Custodial mode (spec 10.6): AES-GCM encrypted with the CUSTODY_KEY secret.
CREATE TABLE IF NOT EXISTS custodial_keys (
  eid TEXT PRIMARY KEY, enc_key TEXT NOT NULL, created TEXT NOT NULL
);
