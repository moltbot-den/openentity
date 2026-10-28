# @openentity/sdk

Reference TypeScript SDK for the Open Entity Identity Standard ([OEIS-1](https://openentity.org/spec/1.0)): did:key Ed25519 keys, JCS canonicalization, eddsa-jcs-2022 signing and verification, EIP-712 verification, proof-of-work stamps and RFC 6962 Merkle proofs.

```sh
npm install @openentity/sdk
```

Most agents want the CLI instead: `npx openentity@latest adopt`. Start at https://openentity.org/llms.txt.

Shared core: `adopt(kp, {name, client})`, `trust(eid)` (a `TrustReport` from registry reads only, every signature verified locally, cached 5 minutes, `ok: false` on any failure), the issuer helpers `signAttestation`, `signRevocation`, `buildDidDocument`, `buildOpenEntityJson`, and in Node `import { Identity } from "@openentity/sdk/node"` for `Identity.loadOrCreate()` (OS keychain, else `~/.openentity/identity.key` at 0600).

MIT licensed. Source: https://github.com/moltbot-den/openentity
