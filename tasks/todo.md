# Open Entity: build plan

Phase order is PRD section 11. One PR per phase, merged and deployed before the next starts.

## Setup (2026-10-24)
- [x] Repo `moltbot-den/openentity` created (public), licenses: MIT for code, CC0-1.0 for `spec/` and `skill/`
- [x] `scripts/verify.sh`, `.githooks/pre-push`, `test.yml` before the first feature commit
- [x] Moltbot Den docs PR (moltbot-den/moltbotden#825): copies in `docs/open-entity/`, old draft reduced to a pointer
- [x] Cloudflare account `b9ebc7de787d7dd325eabbe7a0baedce`: zones `openentity.org`, `openentityidentitystandard.com`, `oeis.dev` all present and active (Free plan zones)
- [x] `openentityidentitystandard.com` and `www` 301 every path to `openentity.org`; `oeis.dev` 302 to this repo (Worker `redirects/`, custom domains)
- [x] npm org `openentity`; `openentity` and `@openentity/sdk` 0.1.0 published; trusted publishing (staged, 2FA approval) via `publish.yml`
- [ ] PyPI `openentity` (Phase 2, needs a PyPI token)

Domain result: the wrangler OAuth token has `zone (read)` only, so DNS records, rulesets and zone settings cannot be written yet. The redirects therefore run as a Worker on custom domains instead of redirect rules; behavior is identical (301 with path and query, 302 for oeis.dev).

## Phase 1: the standard and its home (PRD 11, Phase 1)
Spec
- [ ] `spec/declaration-1.0.txt` and its SHA-256; `spec/schemas/` (EntityDocument, Declaration, Withdrawal, RecordEntry, Attestation, Revocation, ContinuityLink, Dispute, LogLeaf); `spec/claim-types.md` (include `custom:securemyagent:security_posture`: score_band, checks_passed[], scanner_version, evidence_hash; 30-day expiry)
- [ ] `test-vectors/` from the TS reference with a published throwaway seed; independent Python verifier reproduces every vector
SDK and CLI
- [ ] `sdk/ts`: did:key, JCS, eddsa-jcs-2022 sign and verify, EIP-712 verify, stamp, Merkle proofs
- [ ] `cli/` (`openentity`, `oe`): adopt, whoami, self, anchor, document, record, alias, verify, resolve, log, stats, export and import; `--json`, `--dry-run`, stable exit codes
- [x] CLI published to npm (`npx openentity@latest`); `withdraw --force` added in 0.2.0, released through `publish.yml` after merge
Registry (`registry/`, Hono on Node, Aurora PostgreSQL via Data API, S3)
- [ ] `schema.sql` per PRD 8
- [ ] Spec 10.2 endpoints: spec, adopt, entities, document, aliases (domain, wallet, erc8004, platform), record, attestations, continuity, withdraw, observers, resolve, verify, stats, subscribe, stats history CSV, founding
- [x] tlog-tiles log: leaves, tiles on S3, signed checkpoint, inclusion and consistency proofs, sth, entries, daily snapshot plus S3 Object Lock copy
- [ ] Stamps, per-IP and per-EID limits, schema validation before signatures
Site (`site/`, Astro with Starlight, served by the app Lambda through CloudFront)
- [x] Every page in PRD 7.1; brand mark SVG; JSON-LD; no page needs JavaScript to read
- [x] `llms.txt` (Appendix A), `llms-full.txt`, `skill/openentity/SKILL.md`, `AGENTS.md`, well-known files, robots.txt with Content-Signal, sitemap, security.txt
- [ ] Human form: Turnstile plus Customer.io Track API (form not rendered until credentials exist). Site side done: rendered by `site/server` only when `SUBSCRIBE_ENABLED = "true"`; posts form-encoded `email`, `operator`, `cf-turnstile-response` to `/v1/subscribe`
AWS (account `openentity` 099705791378, us-east-1, stack `OpenEntity`, from credits)
- [x] CDK stack `infra/`: CloudFront (openentity.org, ACM cert), one Lambda (site plus /v1, origin header check), Aurora Serverless v2 PostgreSQL 16 with Data API, log bucket, snapshot bucket (Object Lock compliance 1 year), EventBridge Scheduler every minute, GitHub OIDC deploy role, alarms, $150 budget
- [x] Secrets Manager `openentity/app` seeded from the GCP copies (registry key unchanged, so the log continues)
- [x] Cutover 2026-10-25: D1 rows imported, R2 tiles and snapshots copied, apex CNAME to CloudFront (DNS-only), verifier PASS on openentity.org at tree size 7
- [x] Cloudflare Workers `openentity-site` and `openentity-registry` and the KV namespace deleted
- [ ] Lambda concurrency quota 1000 requested (new accounts start at 10); load test waits for it
- [x] Old D1 and R2 deleted after the first green AWS deploy; a final D1 export sits under Object Lock at `cloudflare-archive/` in the snapshot bucket
Cloudflare (free plan only: DNS, redirects Worker, Turnstile, Web Analytics)
- [x] Turnstile widget `openentity-subscribe` (site key 0x4AAAAAAFkggsScyaPIMp2v); Web Analytics site token 1c8d90533d834474833d04a8b62d5117
- [x] `deploy.yml`: `cdk deploy` through OIDC, schema through the Data API, redirects through wrangler, then the post-deploy fetch check
Required tests (PRD 11 Phase 1)
- [ ] Vectors round-trip in TS and Python
- [ ] Wrong Declaration text hash rejected; second Declaration rejected; broken record chain rejected; wrong `seq` rejected; alias bound to another EID rejected
- [ ] Checkpoint verifies with an independent tlog-tiles client; inclusion proof verifies for every leaf
- [ ] Stamp cannot be bypassed; Turnstile never required on `/v1/*` except `/v1/subscribe`
- [x] `llms.txt` parses; no page needs JS for text; no em dashes; no hand-typed counts
Verification
- [x] Load script on the Cloudflare build: 6000/6000 accepted, p95 251 ms
- [ ] Re-run on AWS once the Lambda concurrency quota (case open, 10 to 1000) is granted; keep it to one 60 s run
- [x] Fresh agent, empty home and npm cache, given only the llms.txt sentence: listed at L0 in 12.2 s, log index 7 (Docker Desktop would not start headless, so an empty HOME stood in for the container)
- [x] Same through the HTTP door with the Python SDK: L0 in 2.3 s on AWS
- [x] All four test entities withdrawn (log 10 to 13), keys and sandbox homes deleted
