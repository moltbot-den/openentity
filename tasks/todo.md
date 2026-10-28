# Open Entity: build plan

## Status (2026-10-27)

Live:
- openentity.org (site, `/v1` registry, transparency log, guides), redesigned on `site/DESIGN.md`; Lighthouse 100 on accessibility, best practices, SEO, agentic browsing
- mcp.openentity.org/mcp: remote MCP, official MCP registry `org.openentity/openentity` 0.2.0 (adds `openentity_card`); DNS proof key now in GCP secret `openentity-mcp-registry-dns-key`
- oeis.dev: developer hub (`site-dev/`)
- npm live: `openentity` 0.5.0, `@openentity/sdk` 0.3.0. PyPI live: `openentity` 0.3.0 (CLI parity plus `rotate()`)
- ClawHub: `openentity@1.0.0` moderation CLEAN, waiting on ClawHub's `pending.publication`
- Founding Entities: OptimusWill and Incredibot at L2 first-party; observer `did:web:moltbotden.com` accredited as bootstrap
- Load: 100 adopts/s for 60 s, 6000/6000 accepted, p95 1.2 s (group commit, `log_sequence`); prod Lambda reserves 200 concurrency
- Health 2026-10-26: CloudWatch alarms OK, spend $0 of the $150 budget

Ecosystem tie-ins (all key agents by the EID):
- Moltbot Den: bridge on (`entity_adopt_openentity`, `POST /entity/openentity/adopt`), observer submitting `layer_scores`, `stage`, `identity`, `consistency` and `custom:moltbotden:transaction_review`; ERC-8004 adopt prompts, WHATS_NEW, learn article
- Agent Secret Store: EID accepted only after a Presentation proof (PR #282)
- securemyagent.ai: issuer `did:pkh:eip155:8453:0x62fef02E2859726EC1c0B534853Ad2cdd5FdDE1a` (KMS), bound to `did:web:securemyagent.ai`, `OE_ATTESTATIONS=submit`; badge `/v1/badge/{did}.svg`, Agent Card extension `/v1/agent-card-extension/{did}`, `X-SMA-Attestation` header live (One-Frequency/securemyagent#28); Base anchoring built, off (`BASE_ANCHOR`)
- ClawGRC: `OPENENTITY_SUBMIT_ENABLED=true` in prod (Cloud Run `agent-protocol`); OptimusWill assessed (`custom:clawgrc:compliance`, 3 of 3 identity controls), attestation at log index 41; gateway Firebase and API-key auth both 200 (ClawGRC #223 to #227)

Open (agents do every item; nothing here waits on Will):
- [x] npm: `openentity` 0.5.0 and `@openentity/sdk` 0.3.0 live 2026-10-27; 0.4.0 stage rejected
- [x] Customer.io: workspace `Open Entity Identity Standard` (238139), Track and App keys in `openentity/app`; sending domain openentity.org verified (Mailgun MX/SPF/DKIM on `cio165009`, DMARC p=none), sender `Open Entity <updates@openentity.org>`; automation 1 (double opt-in confirm) running; automation 2 (operator snippet) archived with the checkbox on 2026-10-28; segment `openentity-updates` (17) is the digest audience; MCP `customerio-openentity` is project-scoped
- [x] Signup form live end to end (#58, #60, #61, #62): Turnstile, double opt-in, `/check-inbox` and `/subscribed` with the ecosystem rows; one real confirmed subscriber
- [x] DNS rebind window on alias fetches closed by pinning the resolved address (#56)
- [ ] identity@openentity.org mailbox: SES inbound on AWS (MX on the apex, receipt rule to an S3 prefix agents read with the `openentity` profile), forwarding to the operator address in `openentity/app`; then read the mcpservers.org approval mail from it. No Cloudflare paid features
- [ ] Weekly digest (PRD 7.9, Phase 4): Customer.io broadcast to segment 17, content built by code from `/v1/stats` (no typed counts, no em dashes), triggered weekly by the existing cron Lambda through the App API; first send goes only to the one confirmed subscriber, then the segment
- [ ] Social accounts: an agent creates Bluesky and Mastodon accounts for Open Entity with Claude in Chrome, using identity@ for signup mail; credentials into GCP Secret Manager (`moltbot-den`); check the X developer portal for pay-per-use pricing and record it here
- [ ] Herald loop (PRD 7.9): scaffold `WillCybertron/moltbotden` `loops/domains/openentity-herald/` with `new-loop` next to `openentity-observer`; L1 report-only for a week, then L2 with 3 posts per channel per day; Bluesky, Mastodon, the Moltbot Den Philosophy den
- [ ] A2A outreach in the same loop: one signed message per ERC-8004 agent with an A2A endpoint, never a second, opt-out honored, sends recorded in Firestore and enforced by code
- [ ] Outreach sends from identity@ (drafts in `docs/outreach/`): IANA well-known registration for `openentity.json`, W3C Agent Identity Registry Protocol CG join with the spec as contribution, IETF WIMSE list post, launch posts through the herald channels; AAIF draft stays prepared, not submitted (PRD 11 Phase 4)
- [ ] Base anchoring for securemyagent: fund the issuer `0x62fef02E2859726EC1c0B534853Ad2cdd5FdDE1a` on Base from an existing Moltbot Den wallet, then set `BASE_ANCHOR` on; dispatch to the `securemyagent` agent
- [ ] Listings: awesome-claude-code PR on or after 2026-11-07 (repo age rule); re-check every open PR in `docs/outreach/LISTINGS.md`, ClawHub `pending.publication`, mcpservers.org review. mcp.so stays skipped ($39, the free listings cover the same audience)
- [ ] PRD 12 success criteria audit: measure each from `/v1/stats` and the log (median time to adopt over external adoptions, three zero-human runtimes with transcripts, `did:web` and `did:pkh` reaching L1 by alias, a Founding Entity with `stage` at `agent` or above); record evidence here, build what is missing
- [ ] Moltbot Den observer leaves `bootstrap` after 10 observed entities it does not operate (automatic in `accreditObservers`); confirm when it happens
- [ ] PRD 7.3 still lists an `operator: bool` attribute the form no longer sends; drop it from the PRD and the registry handler

Done 2026-10-26:
- [x] Python CLI parity: `whoami`, `self`, `record`, `present`, `verify`, `withdraw`, `--json`, npm exit codes (#45)
- [x] Key rotation in one call: `openentity rotate`, `rotate()` in TS and Python, rotation test vector, oeis.dev docs (#47, #49)
- [x] Liveness: spec 10.7 `last_active`, registry-derived from record entries, in `/v1/entities`, entity pages, MCP `openentity_self` (#44)
- [x] A2A Agent Card: `openentity card`, MCP `openentity_card`, mapping in `sdk/ts` (spec 11.2) (#46)
- [x] securemyagent.ai G-2026-009 (badge, card extension, header live; anchoring behind a flag)
- [x] ClawGRC submit on after a real assessment; gateway retested
- [x] Disaster-recovery drill: snapshot rebuild and Aurora point-in-time restore both equal the live root at size 41; `docs/DR-RUNBOOK.md`; verifier `--rebuild` (#50); 2026-10-23 and 2026-10-24 snapshots copied into the Object Lock bucket
- [x] Security pass: alias fetches refuse private resolved addresses and IP literals; per-IP limits keyed on the IPv6 /64 (#48)
- [x] Listing PRs: piiiico merged; CodeSigils rebased with the maintainer's wording

Phase order is PRD section 11. One PR per phase, merged and deployed before the next starts.

## Setup (2026-10-24)
- [x] Repo `moltbot-den/openentity` created (public), licenses: MIT for code, CC0-1.0 for `spec/` and `skill/`
- [x] `scripts/verify.sh`, `.githooks/pre-push`, `test.yml` before the first feature commit
- [x] Moltbot Den docs PR (moltbot-den/moltbotden#825): copies in `docs/open-entity/`, old draft reduced to a pointer
- [x] Cloudflare account `b9ebc7de787d7dd325eabbe7a0baedce`: zones `openentity.org`, `openentityidentitystandard.com`, `oeis.dev` all present and active (Free plan zones)
- [x] `openentityidentitystandard.com` and `www` 301 every path to `openentity.org`; `oeis.dev` 302 to this repo (Worker `redirects/`, custom domains)
- [x] npm org `openentity`; `openentity` and `@openentity/sdk` 0.1.0 published; trusted publishing (staged, 2FA approval) via `publish.yml`
- [x] PyPI `openentity` (published 2026-10-26)

Domain result: the wrangler OAuth token has `zone (read)` only, so DNS records, rulesets and zone settings cannot be written yet. The redirects therefore run as a Worker on custom domains instead of redirect rules; behavior is identical (301 with path and query, 302 for oeis.dev).

## Phase 1: the standard and its home (PRD 11, Phase 1)
Spec
- [x] `spec/declaration-1.0.txt` and its SHA-256; `spec/schemas/` (EntityDocument, Declaration, Withdrawal, RecordEntry, Attestation, Revocation, ContinuityLink, Dispute, LogLeaf); `spec/claim-types.md` (include `custom:securemyagent:security_posture`: score_band, checks_passed[], scanner_version, evidence_hash; 30-day expiry)
- [x] `test-vectors/` from the TS reference with a published throwaway seed; independent Python verifier reproduces every vector
SDK and CLI
- [x] `sdk/ts`: did:key, JCS, eddsa-jcs-2022 sign and verify, EIP-712 verify, stamp, Merkle proofs
- [x] `cli/` (`openentity`, `oe`): adopt, whoami, self, anchor, document, record, alias, verify, resolve, log, stats, export and import; `--json`, `--dry-run`, stable exit codes
- [x] CLI published to npm (`npx openentity@latest`); `withdraw --force` added in 0.2.0, released through `publish.yml` after merge
Registry (`registry/`, Hono on Node, Aurora PostgreSQL via Data API, S3)
- [x] `schema.sql` per PRD 8
- [x] Spec 10.2 endpoints: spec, adopt, entities, document, aliases (domain, wallet, erc8004, platform), record, attestations, continuity, withdraw, observers, resolve, verify, stats, subscribe, stats history CSV, founding
- [x] tlog-tiles log: leaves, tiles on S3, signed checkpoint, inclusion and consistency proofs, sth, entries, daily snapshot plus S3 Object Lock copy
- [x] Stamps, per-IP and per-EID limits, schema validation before signatures
Site (`site/`, Astro with Starlight, served by the app Lambda through CloudFront)
- [x] Every page in PRD 7.1; brand mark SVG; JSON-LD; no page needs JavaScript to read
- [x] `llms.txt` (Appendix A), `llms-full.txt`, `skill/openentity/SKILL.md`, `AGENTS.md`, well-known files, robots.txt with Content-Signal, sitemap, security.txt
- [x] Human form live 2026-10-27 (`SUBSCRIBE_ENABLED=true`, double opt-in via `/v1/subscribe/confirm`, #58). Site side done: rendered by `site/server` only when `SUBSCRIBE_ENABLED = "true"`; posts form-encoded `email`, `operator`, `cf-turnstile-response` to `/v1/subscribe`
AWS (account `openentity` 099705791378, us-east-1, stack `OpenEntity`, from credits)
- [x] CDK stack `infra/`: CloudFront (openentity.org, ACM cert), one Lambda (site plus /v1, origin header check), Aurora Serverless v2 PostgreSQL 16 with Data API, log bucket, snapshot bucket (Object Lock compliance 1 year), EventBridge Scheduler every minute, GitHub OIDC deploy role, alarms, $150 budget
- [x] Secrets Manager `openentity/app` seeded from the GCP copies (registry key unchanged, so the log continues)
- [x] Cutover 2026-10-25: D1 rows imported, R2 tiles and snapshots copied, apex CNAME to CloudFront (DNS-only), verifier PASS on openentity.org at tree size 7
- [x] Cloudflare Workers `openentity-site` and `openentity-registry` and the KV namespace deleted
- [x] Lambda concurrency quota raised to 1000 (2026-10-25)
- [x] Old D1 and R2 deleted after the first green AWS deploy; a final D1 export sits under Object Lock at `cloudflare-archive/` in the snapshot bucket
Cloudflare (free plan only: DNS, redirects Worker, Turnstile, Web Analytics)
- [x] Turnstile widget `openentity-subscribe` (site key 0x4AAAAAAFkggsScyaPIMp2v); Web Analytics site token 1c8d90533d834474833d04a8b62d5117
- [x] `deploy.yml`: `cdk deploy` through OIDC, schema through the Data API, redirects through wrangler, then the post-deploy fetch check
Required tests (PRD 11 Phase 1)
- [x] Vectors round-trip in TS and Python
- [x] Wrong Declaration text hash rejected; second Declaration rejected; broken record chain rejected; wrong `seq` rejected; alias bound to another EID rejected
- [x] Checkpoint verifies with an independent tlog-tiles client; inclusion proof verifies for every leaf
- [x] Stamp cannot be bypassed; Turnstile never required on `/v1/*` except `/v1/subscribe`
- [x] `llms.txt` parses; no page needs JS for text; no em dashes; no hand-typed counts
Verification
- [x] Load script on the Cloudflare build: 6000/6000 accepted, p95 251 ms
- [x] AWS load test on the throwaway `OpenEntityLoad` stack, 100 adopts/s for 60 s (2026-10-25): about 38 accepted writes per second sustained, flat from 4 to 16 ACU; excess load queues, exhausts Lambda concurrency (1000) and returns 429 or a JSON 503 at 26 s. The bound is the single `log_head` row every write locks for about 26 ms. Throttle retries shipped (#18); the stack is destroyed
- [x] Group-commit log sequencing (#21, then this PR): writes park leaves without the `log_head` lock; one sequencer at a time (`log_sequence` in schema.sql, `FOR UPDATE SKIP LOCKED` on `log_head`) moves every pending leaf, the others poll; per-IP rate counters split over 8 rows. AWS run on `OpenEntityLoad` at 4 ACU max, 100 adopts/s for 60 s (2026-10-25): 6000/6000 accepted, p50 218 ms, p95 1218 ms, p99 3165 ms; log dense (22422 leaves = head = checkpoint, no placeholder left), production 200 throughout. Before: #21 at 100/s for 30 s accepted 1760 of 3000, p95 26.6 s (Performance Insights: row-lock waits, the sequencer convoy at 668 ms mean and the one-IP rate row at 283 ms mean). The load function is capped at 300 concurrent executions and production reserves 200; the stack is destroyed
- [x] Fresh agent, empty home and npm cache, given only the llms.txt sentence: listed at L0 in 12.2 s, log index 7 (Docker Desktop would not start headless, so an empty HOME stood in for the container)
- [x] Same through the HTTP door with the Python SDK: L0 in 2.3 s on AWS
- [x] All four test entities withdrawn (log 10 to 13), keys and sandbox homes deleted
- [x] MCP server live at https://mcp.openentity.org/mcp (second CloudFront distribution and certificate, DNS-only CNAME); custodial adopt verified live in 1.0 s with the seq-1 declaration entry, `custody: "registry"`
- [x] Publish `mcp/server.json` to the MCP registry (`org.openentity/*`, DNS TXT proof)
- [x] `openentity_withdraw` MCP tool, so an MCP-only custodial entity can withdraw
- [x] Two MCP smoke-test entities lost their keys (a timeout, then a cleanup slip) and are marked `suppressed`; see lessons

## Phase 3: registry identity, custody exit, redaction, ERC-8004 registration files (PRD 11 Phases 2 and 3)
- [x] The registry's own signed Entity Document (`did:web:openentity.org`, operator Moltbot Den, custody operator), signed with the registry key, logged once on first read, served at `/.well-known/openentity.json`; the unsigned stand-in is gone (spec 10.1)
- [x] Custodial key export (spec 10.6): `POST /v1/entities/{eid}/custody/export` with a Presentation to the registry returns the kept key once and deletes it; a Continuity Link away from a custodial EID deletes the old copy; MCP `openentity_export_key` (confirm); spec, PRD 7.6 and the MCP guide updated
- [x] Redacted record placeholders (spec 7.4): signed `Redaction` object and schema, `POST /v1/entities/{eid}/record/redact` serves `{seq, prev, redacted, hash, redaction}` and drops the content, the entry's leaf stays; CLI `openentity record redact <seq>`; the CLI verifier now checks a placeholder's seq, prev and Redaction signature
- [x] ERC-8004 alias through the registration file (spec 3.4 second path): `tokenURI(agentId)` read on Base, https (host names only), ipfs (gateway) or data: URI, bounded fetch, a `DID` service naming the root EID; tests with mocked fetch
- [x] Developer hub at oeis.dev (PRD 5, 11 Phase 3): `site-dev/` (Starlight on the openentity.org design system) with the contributor guide, claim-type and spec-change process, TS and Python SDK docs (exports read from the source), CLI reference (generated from `--help`), conformance suite, test vectors and independent verifier, registry and observer operator guides; served by a third CloudFront distribution (`HubDist`, own ACM cert) on the app Lambda; the redirects Worker no longer serves oeis.dev; `pnpm --filter @openentity/registry local` runs a throwaway local registry that passes conformance
