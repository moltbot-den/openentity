-- OpenEntity Account (PLAN sections 2 to 4). Applied statement by statement, idempotently (CREATE ... IF NOT EXISTS).
-- Times are Unix seconds (bigint). JSON lives in text columns: the RDS Data API and PGlite both pass text through unchanged.

CREATE TABLE IF NOT EXISTS accounts (
  id text PRIMARY KEY,                        -- acct_ + 26 base32 chars
  email text,                                 -- the account email, lowercased; notices go here
  email_private boolean NOT NULL DEFAULT false,
  owner_did text UNIQUE,                      -- set at key log genesis
  app_account_token text NOT NULL UNIQUE,     -- UUID for StoreKit appAccountToken and Play obfuscatedAccountId
  created_at bigint NOT NULL,
  deleted_at bigint
);

-- Sign-in methods. One identity at a provider belongs to one account.
CREATE TABLE IF NOT EXISTS methods (
  id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES accounts (id),
  type text NOT NULL CHECK (type IN ('apple', 'google', 'passkey', 'email')),
  subject text NOT NULL,                      -- Apple or Google sub, the passkey credential id, or the email address
  email text,
  data text NOT NULL DEFAULT '{}',            -- passkey: public key, counter, transports, aaguid; apple: the encrypted refresh token
  created_at bigint NOT NULL,
  last_used_at bigint,
  UNIQUE (type, subject)
);
CREATE INDEX IF NOT EXISTS methods_account ON methods (account_id);
CREATE INDEX IF NOT EXISTS methods_email ON methods (email);

-- One session per signed-in device or browser; its refresh tokens form one rotation family.
CREATE TABLE IF NOT EXISTS sessions (
  id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES accounts (id),
  platform text NOT NULL CHECK (platform IN ('ios', 'android', 'web')),
  install_id text,
  device_model text,
  app_version text,
  binding text,                               -- JSON: the App Attest key, or the Android Keystore public key
  amr text NOT NULL,                          -- the sign-in method that opened the session
  auth_time bigint NOT NULL,
  created_at bigint NOT NULL,
  last_used_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  revoked_at bigint,
  revoke_reason text
);
CREATE INDEX IF NOT EXISTS sessions_account ON sessions (account_id);

-- Only the SHA-256 of a refresh token is stored. A token is used once; `successor` is the token that replaced it.
CREATE TABLE IF NOT EXISTS refresh_tokens (
  hash text PRIMARY KEY,
  session_id text NOT NULL REFERENCES sessions (id),
  created_at bigint NOT NULL,
  used_at bigint,
  successor text
);
CREATE INDEX IF NOT EXISTS refresh_tokens_session ON refresh_tokens (session_id);

-- Nonces from POST /v1/auth/nonce: single use, 10 minutes, bound to an install or a browser.
CREATE TABLE IF NOT EXISTS auth_nonces (
  hash text PRIMARY KEY,                      -- SHA-256 hex of the raw nonce
  platform text NOT NULL,
  install_id text,
  flow text NOT NULL,
  state text UNIQUE,
  return_to text,
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  used_at bigint
);

-- 8-digit email codes. Only an HMAC of the code is stored.
CREATE TABLE IF NOT EXISTS email_codes (
  id text PRIMARY KEY,
  email text NOT NULL,
  code_mac text NOT NULL,
  install_id text,
  tries integer NOT NULL DEFAULT 0,
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  used_at bigint
);
CREATE INDEX IF NOT EXISTS email_codes_email ON email_codes (email, created_at);

CREATE TABLE IF NOT EXISTS passkey_challenges (
  id text PRIMARY KEY,
  challenge text NOT NULL,
  mode text NOT NULL CHECK (mode IN ('authenticate', 'register')),
  account_id text,
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  used_at bigint
);

-- Fixed-window counters: key + window start; the primary key makes each increment atomic.
CREATE TABLE IF NOT EXISTS rate_events (
  key text NOT NULL,
  window_start text NOT NULL,
  count integer NOT NULL,
  PRIMARY KEY (key, window_start)
);

-- ---------------------------------------------------------------- core lane: key logs, step-up, signatures, outbox

-- Owner key logs (test-vectors/keylog-1). `line` is the exact JCS entry, stored and served byte for byte.
CREATE TABLE IF NOT EXISTS keylog_entries (
  owner_id text NOT NULL,                     -- base32 SHA-256 of the genesis line: the owner DID's last segment
  seq integer NOT NULL,
  line text NOT NULL,
  hash text NOT NULL,                         -- lowercase hex SHA-256 of line: the next entry's prev
  op text NOT NULL,
  first_seen_at bigint NOT NULL,              -- this service's first sight; the delays it reports run from it
  effective_at bigint NOT NULL,
  PRIMARY KEY (owner_id, seq)
);

-- Step-up requests (POST /v1/step-up). Each is used once (used_at).
CREATE TABLE IF NOT EXISTS step_ups (
  request_id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES accounts (id),
  owner_did text NOT NULL,
  action text NOT NULL,
  params text NOT NULL,                       -- JCS of the normalized params
  payload_digest text NOT NULL,
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  used_at bigint
);
CREATE INDEX IF NOT EXISTS step_ups_account ON step_ups (account_id);

-- The highest WebAuthn signature counter seen per approver passkey (approval/2.0 counter_replayed).
CREATE TABLE IF NOT EXISTS approver_counters (
  owner_did text NOT NULL,
  kid text NOT NULL,
  counter bigint NOT NULL,
  PRIMARY KEY (owner_did, kid)
);

-- RFC 9421 nonces already accepted: SHA-256 hex of keyid|nonce, kept until the signature expires.
CREATE TABLE IF NOT EXISTS sig_nonces (
  key text PRIMARY KEY,
  expires_at bigint NOT NULL
);

-- Signed calls to products that failed and are retried (outbound.ts); `id` is the event id products dedupe on.
CREATE TABLE IF NOT EXISTS outbox (
  id text PRIMARY KEY,
  product text NOT NULL,
  path text NOT NULL,
  body text NOT NULL,
  attempts integer NOT NULL,
  next_at bigint NOT NULL,
  created_at bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox (next_at);

-- ---------------------------------------------------------------- web lane (appends below)
