---
title: Verify an agent at sign-in
description: For platforms. Challenge an agent with a nonce and your audience, verify its signed Presentation with the TypeScript or Python SDK, weigh the attestations it carries and check revocation online.
---

A Presentation is how an agent proves, in one exchange and with no registry call, that it holds the key behind an EID. It is a session proof, so it replaces neither your authorization nor your own API keys: it tells you who is calling and what others have attested about them. The normative text is [Presentations](/spec/1.0#47-presentations-proof-of-control).

## The exchange

1. You issue a challenge: a random `nonce` of at least sixteen bytes (the schema accepts a string of at least sixteen characters) and your own `audience`, your origin URL or your DID. Store the nonce with an expiry and mark it used on first accept.
2. The agent signs a Presentation with that nonce and audience and returns it.
3. You verify it and decide.

Make the nonce single-use and short-lived. The verifier functions check the nonce you pass them equals the one in the Presentation; remembering that you issued it and have not accepted it before is your side of the bargain.

## What the agent sends

The agent produces this with `openentity present --audience <your audience> --nonce <your nonce>`, with the MCP tool `openentity_present`, or with `buildPresentation` in the SDKs. It carries up to twenty of the agent's current, unrevoked attestations so you can weigh trust without a second call:

```json
{
  "spec": "openentity/1.0",
  "type": "Presentation",
  "eid": "did:key:z6Mk...",
  "audience": "https://platform.example",
  "nonce": "4fR9kQ2mT7xL0aVbN3cW8zYd",
  "created": "2026-10-25T19:47:19Z",
  "attestations": [ { "spec": "openentity/1.0", "type": "Attestation", "issuer": "did:web:issuer.example", "subject": "did:key:z6Mk...", "claim_type": "capability", "claim": { "capability": "code-review", "evidence_ref": "..." }, "created": "...", "expires": "...", "proof": { "...": "..." } } ],
  "proof": { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "created": "2026-10-25T19:47:19Z", "verificationMethod": "did:key:z6Mk...#z6Mk...", "proofPurpose": "assertionMethod", "proofValue": "z..." }
}
```

## Verify with the TypeScript SDK

<!-- oe:fixtures -->
```ts
import { verifyPresentation } from "@openentity/sdk";

const result = await verifyPresentation(presentation, {
  audience: "https://platform.example",   // your own, never the one the agent claims
  nonce: issuedNonce,                      // the one you issued for this exchange
});
// { ok: true, eid: "did:key:z6Mk...", errors: [], attestations: [ { claim_type: "capability", issuer: "did:web:issuer.example", ok: true } ] }
```

`ok` covers the Presentation: the schema, a valid signature by the EID itself (not by some other key), your audience, your nonce, and freshness (`maxAgeSeconds`, default `300`, and not from the future beyond a small skew). It never throws on a bad input; it returns `ok: false` with `errors` such as `audience is https://other.example, expected https://platform.example`.

Each carried attestation is checked on its own and reported in `attestations`: its subject must be the presenting EID, it must not have expired, and its signature must verify against its issuer. One bad attestation does not fail the Presentation; it just is not `ok`.

`verifyPresentation` ships in `@openentity/sdk` (`npm install @openentity/sdk`); the Python equivalent is `verify_presentation` in `pip install openentity`.

To check one from the command line, offline, save the Presentation to a file and run the CLI (it needs a version that lists `verify-presentation` in `openentity --help`):

```sh
openentity verify-presentation presentation.json --audience https://platform.example --nonce "$ISSUED_NONCE"
```

```text
ok   attestation capability by did:web:issuer.example
VERIFIED did:key:z6Mk...
```

Exit code zero means verified, three means failed. It resolves `did:key`, `did:pkh` and `did:web` issuers.

## Verify with Python

<!-- oe:fixtures -->
```python
from openentity import verify_presentation

result = verify_presentation(presentation, "https://platform.example", issued_nonce)
# {'ok': True, 'eid': 'did:key:z6Mk...', 'errors': [], 'attestations': [{'claim_type': 'capability', 'issuer': 'did:web:issuer.example', 'ok': True}]}
```

The signature is `verify_presentation(p, audience, nonce_, now=None, max_age=300, resolver=default_resolver)`. The Python SDK is in the repository under `sdk/python` and depends on `cryptography` and `pycryptodome`. Install it from there:

```sh
pip install openentity
```

## Resolve did:web issuers and did:pkh

With no resolver argument both SDKs resolve `did:key` and `did:pkh` offline, with no network. A `did:key` carries its public key. A `did:pkh` carries only an address, and the SDK checks an EIP-712 signature by recovering the signer and comparing it with that address, so wallet-signed objects verify offline too.

An attestation issuer is usually a `did:web`, which needs one HTTPS fetch of its DID document (`https://<domain>/.well-known/did.json`, or `https://<domain>/<path>/did.json` for a path form). Supply a resolver that handles the methods you accept and caches the result:

<!-- oe:fixtures -->
```ts
import { base58btcDecode, publicKeyFromDidKey, type Resolver } from "@openentity/sdk";

const resolver: Resolver = async (did) => {
  if (did.startsWith("did:key:")) return { ed25519: [publicKeyFromDidKey(did)] };
  const pkh = /^did:pkh:eip155:\d+:(0x[0-9a-fA-F]{40})$/.exec(did);
  if (pkh) return { address: pkh[1] };
  if (did.startsWith("did:web:")) {
    const [host, ...path] = did.slice(8).split(":").map(decodeURIComponent);
    const url = path.length ? `https://${host}/${path.join("/")}/did.json` : `https://${host}/.well-known/did.json`;
    const doc = await (await fetch(url, { redirect: "manual" })).json();
    return {
      ed25519: (doc.verificationMethod ?? [])
        .filter((m: any) => typeof m.publicKeyMultibase === "string" && m.publicKeyMultibase.startsWith("z6Mk"))
        .map((m: any) => base58btcDecode(m.publicKeyMultibase.slice(1)).slice(2)),
    };
  }
  throw new Error(`unsupported method ${did.split(":")[1]}`);
};

await verifyPresentation(presentation, { audience, nonce, resolver });
```

<!-- oe:fixtures -->
```python
import json, urllib.request
from openentity import verify_presentation, default_resolver, base58btc_decode

def resolver(did: str) -> dict:
    if did.startswith("did:web:"):
        host, *path = did[8:].split(":")
        url = f"https://{host}/{'/'.join(path)}/did.json" if path else f"https://{host}/.well-known/did.json"
        doc = json.load(urllib.request.urlopen(url, timeout=10))
        return {"ed25519": [base58btc_decode(m["publicKeyMultibase"][1:])[2:]
                            for m in doc.get("verificationMethod", [])
                            if m.get("publicKeyMultibase", "").startswith("z6Mk")]}
    return default_resolver(did)

verify_presentation(presentation, "https://platform.example", issued_nonce, resolver=resolver)
```

The registry resolves the same methods, and you can ask it instead: `GET /v1/resolve/<did>` returns `{did, didDocument}` for `did:key`, `did:pkh`, `did:web` and `did:plc`. Prefer resolving locally for any decision that matters, since the registry is a mirror, not a source of truth ([Security considerations](/spec/1.0#12-security-considerations)). The `did:webvh` and `did:plc` methods exist in the standard; the SDKs do not resolve them for you, so bring a resolver if you accept them.

## Weigh the attestations

A valid Presentation proves control of the key. It proves nothing about trustworthiness. What it carries is claims by other parties, and you choose whose claims count. A reasonable policy:

- Accept an attestation only from issuers on your own allow-list. Publish that list as your trust policy at `/.well-known/openentity.json` under `extensions["openentity:trust_policy"]`, so agents know what you will accept.
- Check `expires` (the SDK already does) and the claim type. Ignore claim types you do not know; the standard says to. The core types and the registered custom types are in [the claim types](https://github.com/moltbot-den/openentity/blob/main/spec/claim-types.md).
- Treat an attestation whose issuer is the agent's own operator as `first-party`, weighed apart from independent ones.
- Do not use one global score. Weigh each issuer yourself.

## Check revocation online

Revocation needs the issuer or a registry, so an offline verifier cannot know. When you are online, ask the registry for the entity's attestations and match what the agent carried by hash:

<!-- oe:fixtures -->
```ts
import { canonicalize, sha256Hex } from "@openentity/sdk";

const rows = (await (await fetch(`https://openentity.org/v1/entities/${result.eid}/attestations`)).json()).attestations;
for (const carried of presentation.attestations ?? []) {
  const hash = await sha256Hex(canonicalize(carried));
  const row = rows.find((r: any) => r.sha256 === hash);
  const state = !row ? "unknown to the registry" : row.revoked_at ? "revoked" : row.expired ? "expired" : "current";
  // row also has: label ("first-party" or "independent"), accredited, issuer_level, disputed, revocation
}
```

Each row is `{sha256, attestation, issuer_level, accredited, bootstrap, label, inherited_from, expired, revoked_at, disputed, revocation, log_index}`. Treat `revoked_at` as a rejection. Treat `disputed: true` as a flag to read the dispute (`GET /v1/entities/<eid>/disputes`), not as a verdict: only the issuer can revoke. An offline verifier should record the attestation as unchecked for revocation and re-check later.

## Do not log or forward Presentations

A Presentation is bound to your audience and your nonce and is useless elsewhere, but it is still a signed statement. Do not submit it to a registry; the standard says it is never logged. Reject any Presentation whose audience is not yours, even if it verifies.
