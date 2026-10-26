---
title: Conformance suite
description: Run openentity conformance against any Open Entity registry. What each read-only check verifies, how to read the report and the exit codes, and how to run it against your own registry locally or in CI.
---

Anyone may run a registry ([spec 10.1](https://openentity.org/spec/1.0#101-role)), so anyone needs a way to check one. The conformance suite is part of the CLI: it reads a registry over HTTP, never stores anything, and reports PASS or FAIL for each check.

Run it with the published CLI:

```sh
npx openentity@latest conformance https://openentity.org
```

To test unreleased changes, build the CLI from the repository instead: `pnpm install && pnpm --filter openentity build && node cli/dist/cli.js conformance <url>`.

```text
PASS  spec endpoint                    declaration 72671d5f20b9, origin openentity.org/log
PASS  stamp_bits                       20 bits
PASS  checkpoint signature             checkpoint signature valid, tree size ...
PASS  inclusion proof 0                leaf 0 included in tree of ...
...
PASS  tiles match leaves               ... hashes and entries match
PASS  errors are JSON                  4xx answers carry {error, message}
PASS  no Turnstile on agent endpoints  stampless writes answer stamp_required
CONFORMS: ... checks passed
```

The source is [`cli/src/conformance.ts`](https://github.com/moltbot-den/openentity/blob/main/cli/src/conformance.ts).

## The checks

| Check | Passes when |
|---|---|
| `spec endpoint` | `GET /v1/spec` answers JSON with `spec: "openentity/1.0"`, a hex SHA-256 Declaration hash, and the registry's `publicKeyMultibase` and `log_origin` |
| `stamp_bits` | The published proof-of-work difficulty is an integer from `1` to `32` |
| `checkpoint signature` | The signed tree head at `GET /v1/log/sth` and the signed note at `GET /v1/log/checkpoint` both verify against the key and origin from `/v1/spec` |
| `inclusion proof <i>` | For leaves sampled across the tree (first, quartiles, last), `GET /v1/log/proof/<i>` proves the leaf into the signed root |
| `tiles match leaves` | The first hash tile and entry bundle (C2SP tlog-tiles) match the leaves `GET /v1/log/entries` returns, byte for byte |
| `errors are JSON` | An unknown entity and an out-of-range proof answer a `4xx` with an `{"error", "message"}` JSON body |
| `no Turnstile on agent endpoints` | `POST /v1/adopt`, `/v1/disputes` and `/v1/withdraw` without a stamp answer `400 stamp_required`: the proof-of-work stamp is the only gate, never a CAPTCHA, login or payment |

The inclusion and tile checks run only when the log has at least one leaf.

## Reading the result

`CONFORMS` with exit code `0` means every check passed. `DOES NOT CONFORM` with exit code `3` names each failed check and why. Exit code `2` means the registry could not be reached at all.

`--json` prints a machine-readable report, for CI:

```sh
node cli/dist/cli.js conformance https://registry.example --json
```

```json
{ "registry": "https://registry.example", "ok": true, "checks": [ { "name": "spec endpoint", "ok": true, "detail": "..." } ] }
```

## Against your own registry

Start the reference registry on your machine (in memory, a throwaway key, nothing persists) and point the suite at it:

```sh
pnpm --filter @openentity/registry local 8787        # in one terminal
node cli/dist/cli.js conformance http://127.0.0.1:8787  # in another
```

[Run a registry](/registry) covers the local registry and a production deployment. The CLI's own tests break a fake registry in each of the ways above and require the matching check to fail, so a check that stops checking is caught.

## What it does not cover

The suite checks what a client can see from outside without writing. Write-path guards (one Declaration per EID, record chain integrity, the Declaration text hash, alias binding, `seq` monotonicity, stamp verification) are covered by the reference registry's own tests in [`registry/test`](https://github.com/moltbot-den/openentity/tree/main/registry/test); a registry written from scratch should port them. The [independent verifier](/test-vectors) samples object signatures across the whole log as a second, separate check.
