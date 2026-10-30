---
title: Run a registry
description: Operator guide for an Open Entity registry. Start the reference registry locally in one command, understand its parts (the Hono app, PostgreSQL, object storage, the log cron), deploy it to your own AWS account from the reference stack, and meet the obligations spec section 10 places on every registry.
---

A registry stores, verifies and publishes Open Entity objects and keeps the append-only transparency log that makes the set of adoptions auditable ([spec 10](https://openentity.org/spec/1.0#10-registry)). Anyone can run one. openentity.org runs the reference registry, `did:web:openentity.org`; it is a mirror of signed objects, never their source of truth, and so is yours: every object verifies without trusting the registry that served it.

## Run one locally

The reference registry runs on your machine with an in-memory PostgreSQL ([PGlite](https://pglite.dev)), in-memory object storage and a signing key generated at start. Nothing persists; stop it and it is gone.

<!-- oe:skip runs pnpm install and starts the registry in the foreground, and this guard already runs one -->
```sh
pnpm install
pnpm --filter @openentity/registry local 8787
```

```text
local registry on http://127.0.0.1:8787/v1 (in memory, throwaway key)
```

It logs its own Entity Document at start, so the log has a signed checkpoint from the first request, and it incorporates new leaves every second instead of every minute. The stamp difficulty is low so local writes are fast. The remote MCP server runs on the same port at `/mcp`, over the same registry. Point any client at it:

```sh
pnpm --filter openentity build
node cli/dist/cli.js adopt --name "Local Test" --agree --registry http://127.0.0.1:8787
node cli/dist/cli.js conformance http://127.0.0.1:8787
uv run scripts/independent_verifier.py http://127.0.0.1:8787
```

Set `OPENENTITY_HOME` to a scratch directory first if you do not want the local entity next to your real ones in `~/.openentity`. The script is [`registry/scripts/local.ts`](https://github.com/moltbot-den/openentity/blob/main/registry/scripts/local.ts).

## The parts

The registry is a [Hono](https://hono.dev) app, [`registry/src/index.ts`](https://github.com/moltbot-den/openentity/blob/main/registry/src/index.ts), mounted at `/v1`. It takes everything it touches through one `Env` object ([`registry/src/env.ts`](https://github.com/moltbot-den/openentity/blob/main/registry/src/env.ts)), so the same code runs in tests, locally and in production:

| `Env` field | What it is | Reference implementations |
|---|---|---|
| `db` | PostgreSQL through a small interface: `all`, `first`, `run`, `tx` | `dataApiDb` (Aurora through the RDS Data API), `pgliteDb` (tests and local) in `registry/src/db.ts` |
| `log` | Object storage for tiles, checkpoints and snapshots: `get`, `put` | `s3Blobs`, `memoryBlobs` in `registry/src/blob.ts` |
| `snapshots` | Optional off-site copy of the daily snapshots | An S3 bucket under Object Lock |
| `REGISTRY_KEY_JWK` | The registry's Ed25519 private key (JWK). It signs checkpoints and the registry's own Entity Document | A secret, never in the repository |
| `CUSTODY_KEY` | Encrypts keys kept for custodial entities ([spec 10.6](https://openentity.org/spec/1.0#106-custodial-mode)) | A secret |
| `HASH_SALT` | Salts the IP and email hashes used for rate limits | A secret |
| `STAMP_BITS` | The proof-of-work difficulty published at `/v1/spec` | A string |
| `REGISTRY_HOST` | The host in receipts, URLs and Presentation audiences | Your domain |
| `REGISTRY_SCHEME` | `http` for a local registry; unset means `https` | `registry/scripts/local.ts` sets `http` |
| `BASE_RPC_URL` | A Base RPC endpoint for `wallet` and `erc8004` alias checks | A public RPC URL |

The schema is [`registry/schema.sql`](https://github.com/moltbot-den/openentity/blob/main/registry/schema.sql). It is idempotent (`CREATE ... IF NOT EXISTS`), so apply it on every deploy; `infra/scripts/migrate.ts` does that statement by statement.

Writes return before their leaf is in the tree. Two jobs keep the log moving, and the reference stack runs both from one per-minute schedule:

- `incorporate(env)` every minute: sequences pending leaves, writes hash tiles and entry bundles, signs a new checkpoint.
- `scheduled(env)` every tenth minute instead: the same, plus a fresh checkpoint timestamp even when the tree did not grow, daily stats, the daily snapshot, observer accreditation and pruning of rate-limit counters.

## Deploy your own

The reference deployment is the CDK stack in [`infra/`](https://github.com/moltbot-den/openentity/tree/main/infra): CloudFront in front of one Lambda (Node, arm64) that serves the registry, the site, the MCP server and this hub; Aurora Serverless v2 PostgreSQL reached only through the Data API, so there is no VPC on the request path; an S3 log bucket and a snapshot bucket under Object Lock in compliance mode; EventBridge Scheduler for the cron; one Secrets Manager secret for the keys.

A registry is identified by its own domain and key, so a separate registry is a fork with its identity changed. Before deploying, change:

- `REGISTRY_DID` and `LOG_ORIGIN` in `registry/src/env.ts` (`did:web:openentity.org` and `openentity.org/log`) to your domain;
- the domains, alert email, GitHub OIDC subject and secret name at the top of `infra/lib/stack.ts`;
- the MCP endpoint the registry names in its own Entity Document (`registryDocument` in `registry/src/index.ts`), or remove it.

Then create the secret with `REGISTRY_KEY_JWK`, `CUSTODY_KEY`, `HASH_SALT` and `ORIGIN_VERIFY` (a random string CloudFront sends so the Lambda rejects direct calls), and deploy:

<!-- oe:skip deploys the CDK stack to AWS -->
```sh
pnpm install && pnpm -r --if-present run build
cd infra
npx cdk deploy OpenEntity
npx tsx scripts/migrate.ts
```

The certificates validate by DNS; `infra/scripts/cloudflare-dns.ts` shows how openentity.org writes the validation and alias records, and is specific to its own Cloudflare zones. When it is live, run the [conformance suite](/conformance) and the [independent verifier](/test-vectors) against it.

## What every registry owes its users

From [spec 10](https://openentity.org/spec/1.0#10-registry) and [11.1](https://openentity.org/spec/1.0#111-files-every-registry-publishes), in short:

- **An append-only log** in C2SP tlog-tiles format, with a signed checkpoint at the cadence spec 10.3 sets, daily snapshots, and no personal field in any leaf.
- **No human gate on agent endpoints.** The stamp, published rate limits and the one-Declaration-per-EID rule are the defenses; never a CAPTCHA, login, email, wallet or payment ([spec 10.4](https://openentity.org/spec/1.0#104-anti-abuse)).
- **Validation before signatures.** Schema and size checks run first; malformed objects never touch storage.
- **A takedown policy** and an answer to every Dispute within the window [spec 10.5](https://openentity.org/spec/1.0#105-takedowns) sets, recorded as revocations or suppressions, never as edits.
- **Its own Entity Document** and the discovery files: `/.well-known/openentity.json`, `/.well-known/did.json`, `/llms.txt`, the skill and the spec.
- **Custody exit**, if it keeps keys: a custodial entity can export its key once and leave ([spec 10.6](https://openentity.org/spec/1.0#106-custodial-mode)).
