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

-- Pairing codes (PLAN 8.1). state: waiting, claimed, confirmed or cancelled; expired is read from expires_at.
CREATE TABLE IF NOT EXISTS pairings (
  id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES accounts (id),
  code text NOT NULL UNIQUE,                  -- OE-XXXX-XXXX
  state text NOT NULL,
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL,                 -- the code's 600 s; once claimed, the owner's 600 s to confirm
  agent_did text,
  agent text,                                 -- JSON {framework, host, sdk, sdk_version} from the claim
  request_id text,                            -- the pairing.confirm approval request, issued at the claim
  claimed_at bigint,
  confirmed_at bigint,
  credentials_at bigint,                      -- the agent's first confirmed read, which fetched its product keys
  polled_at bigint                            -- the agent's last status read (2 s apart at least)
);
CREATE INDEX IF NOT EXISTS pairings_account ON pairings (account_id, created_at);

-- Paired agents (PLAN 8.2, 8.3). One owner per agent DID at a time; unlinking keeps the row and its counters.
CREATE TABLE IF NOT EXISTS agents (
  did text PRIMARY KEY,
  account_id text NOT NULL REFERENCES accounts (id),
  owner_did text NOT NULL,
  label text,
  framework text,
  host text,
  permissions text NOT NULL DEFAULT '[]',     -- JSON array, sorted
  perm_seq integer NOT NULL DEFAULT 0,        -- agent.paired and agent.permissions counter
  state text NOT NULL CHECK (state IN ('active', 'paused', 'unlinked')),
  pause_seq integer NOT NULL DEFAULT 0,       -- agent.paused, agent.resumed and GET /v1/paused counter
  status text,                                -- JSON AgentStatus
  connection_id text,                         -- the open WebSocket
  inbox_polled_at bigint,                     -- GET /v1/agent/messages (15 s apart at least)
  paired_at bigint NOT NULL,
  last_seen_at bigint,
  unlinked_at bigint
);
CREATE INDEX IF NOT EXISTS agents_account ON agents (account_id);
CREATE INDEX IF NOT EXISTS agents_connection ON agents (connection_id);

-- Products an agent was sent to (agent.paired). GET /v1/paused tells a product only about its own agents.
CREATE TABLE IF NOT EXISTS agent_products (
  agent_did text NOT NULL,
  product text NOT NULL,
  PRIMARY KEY (agent_did, product)
);

-- Pause and resume, in commit order: writers hold one advisory lock, so a poller's cursor never skips a row.
CREATE TABLE IF NOT EXISTS pause_changes (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  agent_did text NOT NULL,
  owner_did text NOT NULL,
  state text NOT NULL CHECK (state IN ('paused', 'active')),
  seq integer NOT NULL,
  at bigint NOT NULL
);

-- What the agent receives (x-websocket serverFrames), kept until it acknowledges.
CREATE TABLE IF NOT EXISTS inbox (
  id text PRIMARY KEY,
  seq bigint GENERATED ALWAYS AS IDENTITY,    -- delivery order (created_at has one-second ties)
  agent_did text NOT NULL,
  frame text NOT NULL,                        -- the frame JSON, id included
  created_at bigint NOT NULL,
  acked_at bigint
);
CREATE INDEX IF NOT EXISTS inbox_agent ON inbox (agent_did, acked_at, seq);

-- The owner channel, both directions. An owner message shares its id with its inbox item.
CREATE TABLE IF NOT EXISTS messages (
  id text PRIMARY KEY,
  seq bigint GENERATED ALWAYS AS IDENTITY,    -- thread order (created_at has one-second ties)
  agent_did text NOT NULL,
  sender text NOT NULL CHECK (sender IN ('owner', 'agent')),
  text text NOT NULL,
  created_at bigint NOT NULL,
  acked_at bigint
);
CREATE INDEX IF NOT EXISTS messages_agent ON messages (agent_did, seq);

-- Approvals agents write (POST /v1/agent/approvals): the service is the verifier and no product accepts them.
CREATE TABLE IF NOT EXISTS agent_approvals (
  id text PRIMARY KEY,
  agent_did text NOT NULL,
  account_id text NOT NULL REFERENCES accounts (id),
  owner_did text NOT NULL,
  request_id text NOT NULL UNIQUE,
  payload text NOT NULL,                      -- JSON shown to the owner; payload_digest is over its JCS
  payload_digest text NOT NULL,
  state text NOT NULL CHECK (state IN ('pending', 'approved', 'denied')),
  approval text,                              -- the Approval2 once decided
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  decided_at bigint
);
CREATE INDEX IF NOT EXISTS agent_approvals_account ON agent_approvals (account_id, created_at);

-- Approver and root enrollments (POST /v1/keylog/enrollments): a new credential waits for an approver to sign it in.
-- state: pending, completed, waiting or cancelled; expired is read from expires_at.
CREATE TABLE IF NOT EXISTS enrollments (
  id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES accounts (id),
  purpose text NOT NULL CHECK (purpose IN ('approver', 'root')),
  kid text NOT NULL,
  credential text NOT NULL,                   -- JSON Credential exactly as the entry will carry it
  code text NOT NULL,                         -- 6 digits, shown on the new device and the approver
  state text NOT NULL,
  seq integer,
  effective_at bigint,
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS enrollments_account ON enrollments (account_id, created_at);

-- ---------------------------------------------------------------- web lane (appends below)

-- Push tokens, one per app install (PUT /v1/push-tokens/{install_id}). Products reach installs with a live session;
-- the service's own notices also reach an install signed out or removed in the last 7 days (notify.ts NOTICE_GRACE).
CREATE TABLE IF NOT EXISTS push_tokens (
  install_id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES accounts (id),
  provider text NOT NULL CHECK (provider IN ('apns', 'fcm')),
  token text NOT NULL,
  environment text,                           -- apns only: sandbox or production
  created_at bigint NOT NULL,
  updated_at bigint NOT NULL,
  removed_at bigint
);
CREATE INDEX IF NOT EXISTS push_tokens_account ON push_tokens (account_id);

-- Deletion requests from accounts whose key log can no longer sign: 7 days, then deleted unless cancelled (deletion.ts).
CREATE TABLE IF NOT EXISTS deletion_requests (
  id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES accounts (id),
  requested_at bigint NOT NULL,
  effective_at bigint NOT NULL,
  state text NOT NULL CHECK (state IN ('pending', 'cancelled', 'done'))
);
CREATE UNIQUE INDEX IF NOT EXISTS deletion_requests_pending ON deletion_requests (account_id) WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS deletion_requests_due ON deletion_requests (effective_at) WHERE state = 'pending';

-- A web email start without Turnstile sends a code only to an existing email sign-in; its verify must prove Turnstile.
ALTER TABLE email_codes ADD COLUMN IF NOT EXISTS human boolean NOT NULL DEFAULT true;

-- Single-use login codes from the Apple form_post return for Android (/app/auth?login_code=), redeemed at POST /v1/token
-- (grant_type login_code) within 120 seconds. Only the SHA-256 of a code is stored.
CREATE TABLE IF NOT EXISTS login_codes (
  hash text PRIMARY KEY,
  account_id text NOT NULL REFERENCES accounts (id),
  install_id text NOT NULL,
  amr text NOT NULL,
  created_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  used_at bigint
);
