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
