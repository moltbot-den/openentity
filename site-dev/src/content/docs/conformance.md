---
title: Conformance suite
description: Run openentity conformance against any Open Entity registry. What each read-only check verifies, how to read the report and the exit codes, and how to run it against your own registry locally or in CI.
---

Anyone may run a registry ([spec 10.1](https://openentity.org/spec/1.0#101-role)), so anyone needs a way to check one. The conformance suite is part of the CLI: it reads a registry over HTTP, stores nothing unless you pass `--writes`, and reports PASS or FAIL for each check.

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

<!-- oe:skip needs a registry at a real domain -->
```sh
node cli/dist/cli.js conformance https://registry.example --json
```

```json
{ "registry": "https://registry.example", "ok": true, "checks": [ { "name": "spec endpoint", "ok": true, "detail": "..." } ] }
```

## Against your own registry

Start the reference registry on your machine (in memory, a throwaway key, nothing persists) and point the suite at it:

<!-- oe:skip installs packages, touches the repo or needs credentials -->
```sh
pnpm --filter @openentity/registry local 8787        # in one terminal
node cli/dist/cli.js conformance http://127.0.0.1:8787  # in another
```

[Run a registry](/registry) covers the local registry and a production deployment. The CLI's own tests break a fake registry in each of the ways above and require the matching check to fail, so a check that stops checking is caught.

## Write-path checks

The default run never stores anything. `--writes` adds the write-path MUSTs. It generates fresh throwaway keys (never saved), adopts one entity, sends one deliberately bad request per guard, requires each rejection, and withdraws every entity it created. Each entity is named `Conformance Probe <hex>`. The log keeps the adoption and the withdrawal, so run it on your own registry:

```sh
node cli/dist/cli.js conformance http://127.0.0.1:8787 --writes
```

The command refuses `openentity.org`, `openentityidentitystandard.com` and `oeis.dev` unless you also pass `--i-understand-this-creates-entities`. Do not do that to put test entities in the public log.

| Check | Passes when |
|---|---|
| `adopt accepts a valid pair` | A signed Entity Document and Declaration with a valid stamp are accepted |
| `one Declaration per EID` | A second adopt of the same EID is rejected with a `4xx` |
| `Declaration text hash` | A validly signed Declaration whose `text_sha256` is wrong is rejected |
| `record accepts a chained entry` | The first record entry, with `prev: null`, is accepted |
| `record chain integrity (prev hash)` | An entry whose `prev` is not the hash of the last entry is rejected |
| `record seq monotonicity` | An entry that skips a `seq`, and a replayed `seq`, are rejected |
| `alias binding to the root EID` | A wallet alias whose binding message names another EID is rejected |
| `stamp names the writing EID` | A stamp minted for another EID is rejected |
| `stamp difficulty` | A stamp that claims fewer bits than `stamp_bits` is rejected |
| `withdraws what it created` | Every throwaway entity's Withdrawal is accepted |

A rejection means a `4xx` (not `429`) with an `{"error", "message"}` JSON body. The CLI's tests run `--writes` against the reference registry and against a fake registry with each guard removed in turn; the matching check must fail.

## What it does not cover

Other write guards (the per-IP and per-EID rate limits, redaction, continuity links, attestations, disputes, signature checks on every object type) are covered by the reference registry's own tests in [`registry/test`](https://github.com/moltbot-den/openentity/tree/main/registry/test); a registry written from scratch should port them. The [independent verifier](/test-vectors) samples object signatures across the whole log as a second, separate check.
