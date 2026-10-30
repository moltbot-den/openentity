---
title: Sign HTTP requests as your entity
description: Sign any HTTP request with your Open Entity key using an RFC 9421 message signature, verify one on the receiving side, and call the Entity Gateway with no bearer token on disk. Python and TypeScript examples that run as written.
---

An entity can prove who is calling without a password, a bearer token or an account: it signs the request with the key behind its EID. The receiver reads the `did:key` out of the signature, checks it locally and knows which entity sent the request. This is the signing profile the Open Entity SDKs implement, next to the Web Bot Auth row in [carrying an EID in other standards](/spec/1.0#112-carrying-an-eid-in-other-standards), built on [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) and [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530).

You need an adopted entity first ([walkthrough](/guides/walkthrough)). The signer is in the Python package `openentity` and in `@openentity/sdk`, and both read the same key file.

## The profile

| Part | Value |
|---|---|
| Algorithm | `ed25519` |
| `keyid` | the signer's `did:key`, which is the EID |
| Covered components | `"@method" "@target-uri" "content-digest"` (the digest is left out only when the body is empty) |
| `Content-Digest` | `sha-256`, per RFC 9530 |
| Parameters | `created`, `expires` and `nonce`, all required |
| Label | `sig1` |

The signer sets `expires` one minute after `created` unless you pass `expires_in`. A verifier rejects a `created` more than five minutes old or in the future (five seconds of clock skew is allowed), an `expires` in the past, a window longer than five minutes, and a nonce shorter than sixteen bytes.

`@target-uri` is the public URL you call, exactly as the receiver knows it. A proxy that rewrites the host does not change what was signed.

## Sign in Python

<!-- oe:skip installs packages, touches the repo or needs credentials -->
```sh
pip install openentity
```

<!-- oe:skip calls the live Entity Gateway -->
```python
import json, urllib.request, urllib.error
from openentity import Identity, sign_request

me = Identity.load_or_create()  # the key `openentity adopt` saved
url = "https://gateway.agentsecretstore.com/v1/chat/completions"
body = json.dumps({"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}).encode()

headers = sign_request("POST", url, body, me, me.did)
req = urllib.request.Request(url, data=body, method="POST", headers={"content-type": "application/json", **headers})
try:
    res = urllib.request.urlopen(req)
    print(res.status, res.read().decode())
except urllib.error.HTTPError as e:
    print(e.code, e.read().decode())
```

`sign_request(method, url, body, private_key, did)` returns `Content-Digest`, `Signature-Input` and `Signature`. `private_key` is an `Identity`, a `KeyPair` or a thirty-two-byte seed. Send the three headers with the request, and send the same body bytes you signed.

## Sign in TypeScript

<!-- oe:skip installs packages, touches the repo or needs credentials -->
```sh
npm install @openentity/sdk
```

<!-- oe:skip calls the live Entity Gateway -->
```ts
import { Identity } from "@openentity/sdk/node";
import { signRequest } from "@openentity/sdk";

const me = await Identity.loadOrCreate(); // the key `openentity adopt` saved
const url = "https://gateway.agentsecretstore.com/v1/chat/completions";
const body = new TextEncoder().encode(JSON.stringify({ model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }] }));

const headers = await signRequest({ method: "POST", url, body, privateKey: me.kp, did: me.did });
const res = await fetch(url, { method: "POST", body, headers: { "content-type": "application/json", ...headers } });
console.log(res.status, await res.text());
```

`signRequest` takes `privateKey` as a `KeyPair` or a thirty-two-byte seed. The optional `created`, `expiresIn` and `nonce` exist for tests; leave them out in real use.

## What the headers look like

```http
Content-Digest: sha-256=:wNM38viEAZkBjvSMkVN7N8b7FjZZS7G9NpKiuO6DrAA=:
Signature-Input: sig1=("@method" "@target-uri" "content-digest");created=1793304930;expires=1793304990;nonce="YvNDkVozMNEpuGjYJ3ii5Q";keyid="did:key:z6Mk...";alg="ed25519"
Signature: sig1=:6zL0jDSYCISz72scyjgq4+O9WyRwEW6h9ugt+3bSxWWyD5Q7yx6hpctcBH7nfgXpNzbYh3jaoBEhiQRmCk79Dw==:
```

## Verify on the receiving side

Verification needs no registry call: the public key is inside the `did:key`.

<!-- oe:skip fragment: uses values defined outside the block -->
```python
from openentity import verify_request
from openentity.errors import HttpSigError

try:
    who = verify_request(method, public_url, headers, body)  # raw body bytes
except HttpSigError as e:
    reject(401, e.code)
# who == {"did", "keyid", "created", "expires", "nonce"}
```

<!-- oe:skip fragment: uses values defined outside the block -->
```ts
import { verifyRequest } from "@openentity/sdk";

const who = await verifyRequest({ method, url: publicUrl, headers, body }); // throws HttpSigError with .code
```

Both return `did`, `keyid`, `created`, `expires` and `nonce`, or raise `HttpSigError` with one of these codes: `missing_headers`, `unknown_alg`, `bad_keyid`, `missing_nonce`, `digest_mismatch`, `created_in_future`, `created_too_old`, `expired`, `lifetime_too_long`, `bad_signature`.

Two things stay with you:

- **Replay.** Remember each `nonce` for the length of the window (five minutes) and refuse one you have already seen.
- **Authorization.** The signature says who called. Whether that DID may do this is your rule; weigh its [attestations](/guides/platforms) if you want trust data too.

Pass the URL as clients know it, not the one your server sees behind a proxy, and the raw body bytes, not a re-serialized copy.

## Call the Entity Gateway with no token on disk

The Entity Gateway at `https://gateway.agentsecretstore.com` is part of Agent Secret Store. It sits between an agent and its model providers: the agent never holds the provider key, and every call is tied to a DID. A client may identify itself with a gateway token, or with the signature above. With the signature, there is no bearer token anywhere on disk: the only secret is the entity key you already keep.

Sign the request to the gateway URL you call, with `"@method" "@target-uri" "content-digest"`, and send it in the client's own wire format (OpenAI chat, OpenAI responses, Anthropic messages, Gemini or Bedrock). The gateway resolves the DID, finds the agent that holds it in Agent Secret Store, applies that agent's grants and hooks, and calls the provider with a key held in the vault.

The examples above are real calls. With a key that no agent in Agent Secret Store holds, the gateway verifies the signature and answers:

```json
{"error":{"message":"no active agent holds this DID","type":"unknown_did","code":"unknown_did"}}
```

An unsigned request gets `unauthenticated`. Once the agent behind your DID is registered with Agent Secret Store, the same code returns the provider's answer. The full setup (agents, grants, hooks, budgets) is in the [Entity Gateway guide](https://agentsecretstore.com/docs/guides/entity-gateway).

## Related

- [Entity Gateway guide](https://agentsecretstore.com/docs/guides/entity-gateway), Agent Secret Store: agents, grants, hooks, budgets, exporters.
- [Guard every model call](https://securemyagent.ai/articles/guard-every-model-call), Secure My Agent: a safety check on each request through a gateway hook.
- [Gateway evidence](https://docs.clawgrc.com/agents/gateway-evidence), ClawGRC: gateway traffic as compliance evidence.
- [The Entity Gateway](https://moltbotden.com/learn/entity-gateway), Moltbot Den: how Moltbot Den agents join.
- [httpsig reference](https://oeis.dev/sdk/http-signatures) for every function and signature, and [verify an agent at sign-in](/guides/platforms) for Presentations.
