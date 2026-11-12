# Owner key log vectors (keylog-1)

> **WARNING: PUBLISHED THROWAWAY KEYS.** Every secret in `keys.json` is the SHA-256 of a published string. Anyone can sign with these keys. Never use them for anything real.

These vectors define the owner key log of ADR 0007 and `docs/mobile/PLAN.md` section 3.2 byte for byte. The account service writes logs in this format, and every verifier accepts and rejects exactly what these files say. Verifiers: `verifyKeyLog` in `@openentity/sdk`, `verify_key_log` in the Python `openentity` package, `OpenEntityKit` (`sdk/swift`) and `org.openentity:sdk` (`sdk/kotlin`).

Regenerate with `pnpm --filter @openentity/sdk gen:vectors`. A test in `sdk/ts` regenerates them in memory and fails if a committed file differs.

## Entries

A log is JSON Lines. Each line is the RFC 8785 (JCS) form of one entry, byte for byte, with no trailing newline in the line itself. A verifier rejects a line that is not exactly the JCS form of what it parses to, so an entry has one encoding and one hash.

| Field | Value |
|---|---|
| `v` | `1` |
| `seq` | `1` for genesis, then each entry's `seq` is the previous one plus 1 |
| `prev` | `null` for genesis; otherwise the lowercase hex SHA-256 of the previous line's UTF-8 bytes (the full entry, `auth` included) |
| `op` | `genesis`, `add_approver`, `recover`, `replace_root`, `cancel`, `revoke` or `close` |
| `ts` | Unix seconds the signer claims. Informational: no delay or window ever runs from it |
| `body` | Exactly the fields listed for the op below |
| `auth` | The one signature that authorizes the entry |

Every number anywhere in an entry is an integer between -(2^53 - 1) and 2^53 - 1. Strings carry no lone surrogates. JSON objects have no duplicate keys.

### Bodies

| `op` | `body` |
|---|---|
| `genesis` | `{root, approver}`: `root` is a passkey credential; `approver` is the first approver credential, or `null` for a log whose only credential is the root passkey |
| `add_approver` | `{approver}` |
| `recover` | `{approvers}`: one or more new approver credentials |
| `replace_root` | `{root}`: the new root passkey credential |
| `cancel` | `{target}`: the entry hash (the same SHA-256 that `prev` uses) of a `recover` or `replace_root` in this log |
| `revoke` | `{kid}`: the kid of a current approver |
| `close` | `{}` |

### Credentials

```json
{"kid": "...", "type": "p256", "jwk": {"kty": "EC", "crv": "P-256", "x": "...", "y": "..."}, "label": "iPhone", "platform": "ios", "key_storage": "secure_enclave", "attestation": {"type": "app_attest", "verified": true}}
{"kid": "...", "type": "webauthn", "jwk": {...}, "credential_id": "...", "rp_id": "account.openentity.org", "aaguid": "...", "label": "Passkey", "platform": "ios"}
```

- `type` is `p256` (a device key: Secure Enclave, StrongBox or TEE) or `webauthn` (a passkey). The root is always `webauthn`.
- `jwk` has exactly `kty`, `crv`, `x` and `y`; `x` and `y` are the 32-byte coordinates in strict base64url, and the point is on P-256.
- `kid` is the RFC 7638 thumbprint of the JWK: base64url of SHA-256(`{"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}`). The app shows it as the key fingerprint.
- A `webauthn` credential also has a non-empty base64url `credential_id` and `rp_id` equal to `account.openentity.org`.
- Other fields (`label`, `platform`, `key_storage`, `attestation`, `integrity`, `aaguid`) are signed with the entry and shown to people, but no verifier interprets them. The account service checks App Attest, Android Key Attestation and Play Integrity at enrollment and records the result here.

### Signatures

The signed digest is SHA-256 of the JCS form of the entry without `auth`.

| `auth.form` | `auth` |
|---|---|
| `p256` | `{kid, form, signature}`: `signature` is the 64-byte raw `r` then `s`, base64url, ECDSA P-256 over the digest with no further hashing (CryptoKit and the Android Keystore sign the JCS bytes with SHA-256, which gives the same value) |
| `webauthn` | `{kid, form, signature, authenticator_data, client_data_json}`: a WebAuthn `get()` assertion whose challenge is base64url(digest), checked exactly as approval/2.0 checks one (`../approval-2.0/README.md`): type `webauthn.get`, challenge, accepted origin, `crossOrigin` not true, rpIdHash = SHA-256(`account.openentity.org`), user present and user verified flags; `signature` is DER over authenticatorData followed by SHA-256(clientDataJSON) |

**Signatures in entries are canonical,** so nobody can re-encode an entry and give it a second hash (a re-encoded `recover` would no longer match the hash its `cancel` names):

- `s` is in the low half: s <= n/2 for the P-256 group order n. A signer whose platform returns a high `s` replaces it with n - s before it sends the entry. Both are valid ECDSA signatures; only the low one is accepted in a log.
- DER is strict: short-form lengths, minimal positive INTEGERs (a 33-byte INTEGER starts with 0x00 followed by a byte of 0x80 or more), nothing after the sequence.
- base64url is strict: no padding and no non-zero trailing bits.

The form must match the key type: a `webauthn` credential never presents a `p256` signature. `close` is signed in the `p256` form by an account service key; verifiers take those keys as input (`serviceKeys`).

**The signed entry is the step-up.** Adding, recovering or revoking an approver and replacing the root are step-up actions (ADR 0007). The approver's signature over the entry is that step-up: the account service accepts the signed entry and needs no separate approval/2.0 object for it.

## The owner DID

`did:web:account.openentity.org:o:<suffix>`, where the suffix is RFC 4648 base32 of SHA-256(genesis line), lowercase, without padding (52 characters). A replaced log is a different DID. A verifier is given the DID it expects and rejects a log whose genesis does not hash to it.

## Who may sign what

| `op` | Authorized by | Takes effect |
|---|---|---|
| `genesis` | the first approver; the root passkey when `approver` is `null` | at once |
| `add_approver` | a current approver | at once |
| `recover` | the root passkey | at first_seen_at + 86400, unless cancelled first |
| `replace_root` | the root passkey or a current approver | at first_seen_at + 86400, unless cancelled first; at once in a single-credential log |
| `cancel` of a `recover` | a current approver, an approver revoked less than 604800 seconds before, or the root passkey | at once |
| `cancel` of a `replace_root` | a current approver, or an approver revoked less than 604800 seconds before | at once |
| `revoke` | a current approver or the root passkey | at once |
| `close` | an account service key | at once; no entry is accepted after it |

**Single-credential log.** A log whose genesis has `approver: null`. The root passkey is its approver (it signs `add_approver` and approval/2.0) until the first approver takes effect. From then on the root passkey keeps only the powers in the table, permanently: revoking every approver does not make it an approver again. Otherwise a stolen root passkey could revoke the approvers and approve at once, which section 3.3 of the plan rules out.

**Recover.** When a `recover` takes effect, its credentials become the approver set, and every approver current at that moment counts as revoked from that moment (it may sign `cancel` for 7 days and is notified).

**Revoked approvers.** An approver revoked at time `at` may sign `cancel` while the cancel's first_seen_at is less than `at + 604800`, and nothing else ever.

**A key enters a log once.** A kid that any earlier entry introduced (root, approver, recover credential, new root) is never introduced again, even after it is revoked or its entry is cancelled.

**Pending operations.** A `recover` or `replace_root` that waits stays pending until its time comes or a `cancel` names it. It stays valid even if its signer is revoked later; cancel it. A `cancel` whose target has already taken effect, or was already cancelled, is accepted and changes nothing (`late-cancel.json`): rejecting it would stop the verifier from ever accepting a later entry.

## Time

Verifiers pull new entries at least every 60 seconds and record `first_seen_at` for each one: the unix second at which they first held the entry together with its whole chain. It never decreases along the log and is never after `now`. Every delay and window runs from it, never from `ts`.

Before checking entry n, a verifier applies every pending operation whose effective time is at or before entry n's first_seen_at, in order of effective time. After the last entry it applies those due by `now`. So an operation first seen at T takes effect at exactly T + 86400, and a `cancel` first seen at that same second is too late.

## Checks, in order

For each entry, the first failing check names the error:

1. `bad_first_seen`: the first_seen_at list does not match the entries, decreases, or is after `now`.
2. `malformed`: not JSON, duplicate key, not the JCS form, a number that is not a safe integer, a lone surrogate, missing or extra fields, wrong types, unknown `op`, genesis anywhere but first or a first entry that is not genesis, a bad credential (JWK, kid, passkey fields, a root that is not a passkey), or a bad `auth` shape.
3. `closed`: the log was closed by an earlier entry.
4. `bad_seq`, then `bad_prev`.
5. `did_mismatch` (genesis only).
6. `bad_target` (a `cancel` that names no `recover` or `replace_root` of this log; a `revoke` of a key that is not a current approver) or `key_reused` (a credential whose kid is already in the log).
7. `unauthorized`: `auth.kid` may not sign this op at this entry's first_seen_at.
8. `bad_signature` (form mismatch, signature does not verify, high `s`, non-strict DER) or `bad_webauthn` (clientDataJSON or authenticatorData checks).

The verifier returns the first failure with its `seq`, or the state as of `now`:

```json
{"did": "...", "seq": 6, "head": "<hash of the last line>", "root": {credential}, "approvers": [{credential}],
 "revoked": [{"kid": "...", "at": 1794016800}], "pending": [{"seq": 5, "op": "recover", "hash": "...", "effective_at": 1794106800}], "closed": false}
```

`approvers` are the keys that may sign approval/2.0 now, in the order they took effect (the root passkey alone in a single-credential log). `revoked` lists every revoked approver in the order revoked.

## Files

`keys.json`: the throwaway keys (secret, JWK, kid), the web origin and an example Android origin. Every other file is one case:

```json
{"description": "...", "did": "...", "log": ["<line 1>", ...], "first_seen_at": [...], "now": 1794009660,
 "origins": ["https://account.openentity.org", "android:apk-key-hash:..."], "service_keys": [{jwk}],
 "expect": {"ok": true, "state": {..., "root": "<kid>", "approvers": ["<kid>", ...]}}}
```

or `"expect": {"ok": false, "error": "unauthorized", "seq": 2}`. In `expect.state`, `root` and `approvers` are kids. Pass `origins` and `service_keys` to the verifier as given. The Android origin is an example: the real one is the SHA-256 of the Play app signing certificate and is pinned in the SDKs once `assetlinks.json` carries it.

| PLAN 3.2 rule | Valid case | Failure case |
|---|---|---|
| genesis by the first approver | `genesis-device`, `genesis-web-approver` | `did-mismatch`, `genesis-prev-not-null`, `root-not-passkey` |
| single-credential exceptions | `genesis-root-only`, `add-approver-root-only`, `replace-root-root-only` | `root-signs-add-approver`, `root-after-revoking-all` |
| add_approver by a current approver (StrongBox, TEE) | `add-approver` | `unjustified-key-self-signed`, `unjustified-key-unknown-signer` |
| recover after 24 hours, cancellable | `recover-pending`, `recover-effective`, `recover-backdated-ts`, `recover-cancelled-by-approver`, `recover-cancelled-by-root`, `late-cancel` | `recover-by-approver` |
| replace_root after 24 hours, whoever signs | `replace-root-pending`, `replace-root-effective`, `replace-root-by-approver` | `replace-root-not-yet`, `root-cancels-replace-root` |
| revoked approvers cancel, for 7 days only | `recover-cancelled-by-revoked-approver`, `replace-root-cancelled-by-revoked-approver`, `revoked-cancel-last-second` | `revoked-cancel-after-7-days`, `revoked-signs-add-approver`, `revoked-signs-revoke`, `revoked-signs-replace-root` |
| revoke | `revoke`, `revoke-by-root` | `revoke-root` |
| close | `close` | `close-by-approver`, `entry-after-close` |
| chain and encoding | | `bad-prev`, `bad-seq`, `not-canonical`, `duplicate-key`, `fractional-number`, `unknown-op`, `kid-not-thumbprint`, `key-reused`, `cancel-unknown-target`, `first-seen-decreasing` |
| signatures | | `high-s`, `webauthn-high-s`, `webauthn-der-wide-r`, `webauthn-wrong-origin`, `webauthn-wrong-rp`, `webauthn-no-uv`, `form-mismatch`, `tampered-body` |
