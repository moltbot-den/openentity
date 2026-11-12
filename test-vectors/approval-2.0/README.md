# approval/2.0 vectors

> **WARNING: PUBLISHED THROWAWAY KEYS.** Every secret in `keys.json` is the SHA-256 of a published string. Anyone can sign with these keys. Never use them for anything real.

approval/2.0 is ADR 0008: the approval/1.0 protocol of ADR 0004 with the verifier and the owner bound into the digest. Verifiers: `verifyApproval` in `@openentity/sdk`, `verify_approval` in the Python `openentity` package, `OpenEntityKit` (`sdk/swift`) and `org.openentity:sdk` (`sdk/kotlin`). Owner keys come from the owner key log (`../keylog-1/README.md`).

Regenerate with `pnpm --filter @openentity/sdk gen:vectors`.

## Digest

```
digest = SHA-256( UTF-8( "approval/2.0" "|" verifier_did "|" owner_did "|" request_id "|" payload_digest "|" decision "|" expires_at ) )
```

`|` is the byte 0x7C. No field can contain it:

| Field | Form |
|---|---|
| `verifier_did`, `owner_did` | A DID: `did:<method>:` then `[A-Za-z0-9._%:-]`, not ending in `:` |
| `request_id` | 1 to 128 of `[A-Za-z0-9:._-]`, issued by the verifier for the action's current state |
| `payload_digest` | 64 lowercase hex: SHA-256 of the RFC 8785 (JCS) form of the summary the owner saw |
| `decision` | `approve` or `deny` |
| `expires_at` | Unix seconds as decimal ASCII: no sign, no leading zeros. In JSON, an integer |

**Payload summaries** hold strings, booleans, null, arrays, objects and integers between -(2^53 - 1) and 2^53 - 1. Send amounts in minor units or as strings. Every SDK refuses a fractional number or a larger integer, so the verifier and the app always hash the same bytes. For such summaries JCS equals ADR 0004's "keys sorted, no whitespace, non-ASCII as UTF-8", except that JCS sorts keys by UTF-16 code units (`payloads[2]` shows the one difference from Python's `sort_keys`).

## Approval object

```json
{
  "version": "approval/2.0",
  "verifier_did": "did:web:api.agentsecretstore.com",
  "owner_did": "did:web:account.openentity.org:o:...",
  "request_id": "req_7Hk2:42",
  "payload_digest": "...",
  "decision": "approve",
  "expires_at": 1794017100,
  "device_id": "<kid of the signing key in the owner key log>",
  "form": "p256",
  "signature": "...",
  "authenticator_data": "...",
  "client_data_json": "..."
}
```

`authenticator_data` and `client_data_json` appear only for `form: "webauthn"`. All binary fields are base64url without padding.

- **`p256`**: a device key (Secure Enclave, StrongBox, TEE). `signature` is the 64-byte raw `r` then `s` of ECDSA P-256 over the 32-byte digest, with no further hashing. CryptoKit signs the UTF-8 preimage with SHA-256, which gives exactly that.
- **`webauthn`**: a passkey on RP ID `account.openentity.org`. The challenge is base64url(digest). `signature` is DER over authenticatorData followed by SHA-256(clientDataJSON).

Approvals accept either `s` (high or low), as ADR 0004 does. Key log entries accept only the low one (`../keylog-1/README.md`).

## Verifier checks, in order

The first failing check names the error:

1. `malformed`: not a JSON object.
2. `bad_version`: `version` is not `approval/2.0`. Keys in an owner key log sign approval/2.0 only, so approval/1.0 from them is rejected here.
3. `malformed`: a field above has the wrong form; `device_id` is not a string; `form` is not `p256` or `webauthn`; the signature fields are not strict base64url.
4. `wrong_verifier`: `verifier_did` is not this verifier's own DID. Approvals an agent writes through `POST /v1/agent/approvals` name the account service, so no product accepts them.
5. `wrong_owner`: `owner_did` is not the principal that owns the action, or not the DID of the key log it is checked against.
6. `owner_closed`: that key log is closed.
7. `wrong_request`, then `wrong_payload`: the verifier's own `request_id` and its recomputed payload digest, never the client's.
8. `bad_decision`: a decision this action does not accept.
9. `expired` (now >= expires_at), then `expiry_too_far` (expires_at > now + 600).
10. `unknown_key`: `device_id` is not a current approver in the owner's key log. The root passkey is an approver only in a single-credential log.
11. `bad_signature`: the form does not match the key type (a passkey cannot present `p256`).
12. `bad_webauthn` (webauthn only): clientDataJSON is not JSON, its `type` is not `webauthn.get`, the challenge is not base64url(digest), the origin is not accepted, `crossOrigin` is true, rpIdHash is not SHA-256(`account.openentity.org`), or the user present (0x01) and user verified (0x04) flags are not both set.
13. `bad_signature`: the signature does not verify (for webauthn, also a DER encoding that is not strict).
14. `counter_replayed` (webauthn only): the stored and presented signature counters are not both zero and the presented one is not greater (WebAuthn section 7.2). Store the returned counter.

Replay protection is the verifier's (ADR 0004): a request id names one state of one action and is consumed with the decision.

**Origins.** The accepted origins are `https://account.openentity.org` and the OpenEntity Android app's `android:apk-key-hash:<base64url SHA-256 of the app signing certificate>`. `keys.json` carries an example Android origin; the SDKs pin the real one once `assetlinks.json` carries the Play signing fingerprint. Until then pass it as `origins`.

## vectors.json

| Key | What |
|---|---|
| `digests` | The preimage and digest for `approve` and for `deny` |
| `payloads` | Summaries with their JCS form and digest (non-ASCII, UTF-16 key order, escapes) |
| `payloads_invalid` | Summaries every SDK must refuse |
| `key_states` | Owner key states by name: `{did, approvers, closed}` |
| `key_logs` | The key log behind each key state; verifying it (keylog-1 rules, the service key from `keys.json`, `now` from the cases) gives that state |
| `cases` | `{name, description, approval, context, expect}`: verify `approval` with `context` (`verifier_did`, `owner_did`, `request_id`, `payload_digest`, `now`, `origins`, optional `decisions` and `counter`) against `key_states[context.key_state]`. `expect` is `{ok: true, kid, counter}` or `{ok: false, error}` |

Cases cover both decisions, the p256 form (with low and high `s`), WebAuthn from both origins, the single-credential root, the 600-second limit at and past its edge, and one failure per check above: approval/1.0 from a key-log key, the wrong verifier, an agent-written approval, the wrong owner, expiry, a stale request, a changed payload, a key outside the log, the root passkey once approvers exist, tampering, the WebAuthn checks and a replayed counter.
