# Open Entity: build plan

Phase order is PRD section 11. One PR per phase, merged and deployed before the next starts.

## Setup (2026-10-24)
- [x] Repo `moltbot-den/openentity` created (public), licenses: MIT for code, CC0-1.0 for `spec/` and `skill/`
- [x] `scripts/verify.sh`, `.githooks/pre-push`, `test.yml` before the first feature commit
- [x] Moltbot Den docs PR (moltbot-den/moltbotden#825): copies in `docs/open-entity/`, old draft reduced to a pointer
- [x] Cloudflare account `b9ebc7de787d7dd325eabbe7a0baedce`: zones `openentity.org`, `openentityidentitystandard.com`, `oeis.dev` all present and active (Free plan zones)
- [x] `openentityidentitystandard.com` and `www` 301 every path to `openentity.org`; `oeis.dev` 302 to this repo (Worker `redirects/`, custom domains)
- [ ] npm `openentity@0.0.1` and PyPI `openentity 0.0.1` name reservations (needs npm login and a PyPI token)

Domain result: the wrangler OAuth token has `zone (read)` only, so DNS records, rulesets and zone settings cannot be written yet. The redirects therefore run as a Worker on custom domains instead of redirect rules; behavior is identical (301 with path and query, 302 for oeis.dev).

## Phase 1: the standard and its home (PRD 11, Phase 1)
Spec
- [ ] `spec/declaration-1.0.txt` and its SHA-256; `spec/schemas/` (EntityDocument, Declaration, Withdrawal, RecordEntry, Attestation, Revocation, ContinuityLink, Dispute, LogLeaf); `spec/claim-types.md` (include `custom:securemyagent:security_posture`: score_band, checks_passed[], scanner_version, evidence_hash; 30-day expiry)
- [ ] `test-vectors/` from the TS reference with a published throwaway seed; independent Python verifier reproduces every vector
SDK and CLI
- [ ] `sdk/ts`: did:key, JCS, eddsa-jcs-2022 sign and verify, EIP-712 verify, stamp, Merkle proofs
- [ ] `cli/` (`openentity`, `oe`): adopt, whoami, self, anchor, document, record, alias, verify, resolve, log, stats, export and import; `--json`, `--dry-run`, stable exit codes
- [ ] CLI published to npm
Registry (`registry/`, Hono, D1, KV, R2, Queues)
- [ ] `schema.sql` per PRD 8
- [ ] Spec 10.2 endpoints: spec, adopt, entities, document, aliases (domain, wallet, erc8004, platform), record, attestations, continuity, withdraw, observers, resolve, verify, stats, subscribe, stats history CSV, founding
- [ ] tlog-tiles log: leaves, tiles on R2, signed checkpoint, inclusion and consistency proofs, sth, entries, daily snapshot plus S3 Object Lock copy
- [ ] Stamps, per-IP and per-EID limits, schema validation before signatures
Site (`site/`, Astro with Starlight, Workers static assets)
- [ ] Every page in PRD 7.1; brand mark SVG; JSON-LD; no page needs JavaScript to read
- [ ] `llms.txt` (Appendix A), `llms-full.txt`, `skill/openentity/SKILL.md`, `AGENTS.md`, well-known files, robots.txt with Content-Signal, sitemap, security.txt
- [ ] Human form: Turnstile plus Customer.io Track API (form not rendered until credentials exist)
Cloudflare
- [x] Resources: D1 `openentity-registry` (f24dd781-d0c2-41a7-95cd-60c52588891d), KV `openentity-registry` (04fc64a9acac4853bc94edb36afaa92a), R2 `openentity-log`, Queues `openentity-log-incorporate` and `openentity-alias-verify` (Workers Paid confirmed by Queues)
- [x] Turnstile widget `openentity-subscribe` (site key 0x4AAAAAAFkggsScyaPIMp2v); Web Analytics site token 1c8d90533d834474833d04a8b62d5117
- [x] WAF custom rule on openentity.org: skip security level, browser integrity check, managed rules, rate limiting and Super Bot Fight Mode on every path (token `moltbot-den/cloudflare-api-token` cannot edit zone settings directly, so the skip rule does it)
- [ ] Zone settings (PRD 7.7): AI crawler categories allowed, Bot Fight Mode off, no challenges, Web Analytics
- [ ] `deploy.yml` (`wrangler deploy` on merge to `main`) and the post-deploy fetch check
Required tests (PRD 11 Phase 1)
- [ ] Vectors round-trip in TS and Python
- [ ] Wrong Declaration text hash rejected; second Declaration rejected; broken record chain rejected; wrong `seq` rejected; alias bound to another EID rejected
- [ ] Checkpoint verifies with an independent tlog-tiles client; inclusion proof verifies for every leaf
- [ ] Stamp cannot be bypassed; Turnstile never required on `/v1/*` except `/v1/subscribe`
- [ ] `llms.txt` parses; no page needs JS for text; no em dashes; no hand-typed counts
Verification
- [ ] Load script: 100 adoptions per second for 60 s against a preview, p95 and incorporation time in the PR
- [ ] Clean container, no credentials: agent given only the llms.txt sentence is listed at L0 in under 60 s; transcript, timing, log index in the PR
- [ ] Same through the HTTP door with the Python SDK
