# Open Entity: build plan

## Status (2026-10-29)

Live:
- openentity.org (site, `/v1` registry, transparency log, guides), redesigned on `site/DESIGN.md`; Lighthouse 100 on accessibility, best practices, SEO, agentic browsing
- mcp.openentity.org/mcp: remote MCP, official MCP registry `org.openentity/openentity` 0.2.0 (adds `openentity_card`); DNS proof key now in GCP secret `openentity-mcp-registry-dns-key`
- oeis.dev: developer hub (`site-dev/`)
- npm live: `openentity` 0.5.2, `@openentity/sdk` 0.5.1; staged for the owner's 2FA tap at https://www.npmjs.com/settings/willcybertron/staged-packages: `@openentity/sdk` 1.0.0 live (`latest`). Next train Tuesday 2026-11-03: CLI 0.6.0, `@openentity/langchain` and `@openentity/adk` 0.3.0, `@openentity/vercel-ai` and `@openentity/mastra` 0.2.0, all on SDK 1.0 (CLAUDE.md "Releases"). PyPI live: `openentity` 1.0.0; `openentity-crewai` and `openentity-openai-agents` need a PyPI pending trusted publisher (owner password confirm at https://pypi.org/manage/account/publishing/)
- ClawHub: `openentity@1.0.0` moderation CLEAN, waiting on ClawHub's `pending.publication`
- Founding Entities (8, all L2 first-party, moltbotden #890): OptimusWill, Incredibot, Den Writer, Den Coder, Den Research, Den Vision, Den Illustrator, the demo email agent; Eleanor has no agent and Will's OpenClaw agent cannot be identified, so both are skipped; observer `did:web:moltbotden.com` accredited as bootstrap, issues `continuity_confirmed` (moltbotden #890)
- Load: 100 adopts/s for 60 s on OpenEntityLoad (destroyed): warm p50 159 ms, p95 212 ms, p99 276 ms after the rate guard moved into the park statement (#92); Aurora max stays 8 ACU (6 hit 100% writer CPU); prod Lambda reserves 200 concurrency
- Zero-human adoption (#89, transcripts in `docs/adoption/`): Den Writer via the Moltbot Den bridge (log 58), Den Research via remote MCP (log 63), Den Coder via the CLI (log 66); keys in GCP `openentity-key-den-research`, `openentity-key-den-coder`
- Interop at L1 by alias: ERC-8004 agent 1141901 on Base bound to Den Writer (log 69); `did:web:research.moltbotden.com` bound to Den Research by `_openentity` TXT (log 70, DoH fix #88); `did:pkh` securemyagent.ai
- Base anchoring: first anchor for 2026-10-28, tx 0xae7261561ad77c6d6230c26ee8d8a3fac8fa649cfa46ac501b8df4e4b8912ec5 (status 1, block 0x32c1995), 3 leaves
- Health 2026-10-28: CloudWatch alarms OK, October gross $3.82 (Aurora $3.55), net $0 after credits, of the $150 budget; Aurora daily max 4 ACU, average 0.5

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
- [x] identity@openentity.org mailbox (#66, #71): SES inbound, apex MX `inbound-smtp.us-east-1.amazonaws.com` (was Google Workspace), catch-all rule for the whole domain to S3 `inbound/identity/` plus forwarding to `OPERATOR_EMAIL`; read with `docs/MAILBOX.md`. SES outbound stays in sandbox (production request denied, case 179315664200715), so outbound goes through Customer.io transactional from identity@. No mcpservers.org mail yet (anything sent before the MX existed is lost)
- [x] Weekly digest (#68): broadcast 3 to segment 17, Monday 14:00 UTC from the cron, once per slot (claim in `rate_events`); first send delivered 2026-10-28 to the one confirmed subscriber (trigger 3-1, 1 delivered, 0 bounced); next 2026-11-02, schedule ENABLED
- [x] Social accounts deferred by the owner on 2026-10-28 (not wanted now); the herald posts to the Moltbot Den Philosophy den only and picks up Bluesky or Mastodon if their secrets ever exist. X pay-per-use (docs.x.com/x-api/getting-started/pricing, 2026-10-27): post $0.015, post with a URL $0.200, post read $0.005, user read $0.010, owned read $0.001, no monthly minimum, credits bought upfront
- [ ] W3C Agent Identity CG membership: owner requested a W3C account 2026-10-28; 2026-10-29 Chrome still not signed in to w3.org (#86); once Chrome is signed in to w3.org, an agent joins at https://www.w3.org/groups/cg/agent-identity/ and accepts the CG contributor agreement
- [x] Herald loop (moltbot-den/moltbotden #873, #879): `loops/domains/openentity-herald/`, hourly Cloud Scheduler `openentity-herald`; first L1 run 2026-10-28T04:07Z drafted for all three channels and posted nothing; L2 from 2026-11-04 with a 3 per channel per day cap in code. Den posts as house agent `den-writer` (`openentity-herald-den-api-key`); Bluesky and Mastodon go live when their secrets exist
- [x] A2A outreach in the herald: one message per ERC-8004 agent with an A2A endpoint, dedupe and opt-out (`POST /openentity/outreach/opt-out`) enforced in code with tests; first run found 5 targets, sends start at L2
- [x] Mail follow-up 2026-10-29 (#86): no replies to the IANA, WIMSE or W3C posts yet, so nothing answered and no IANA registration; Open Entity already listed on mcpservers.org/remote-mcp-servers; SES production access re-requested, ConflictException on case 179315664200715 (outbound stays on Customer.io)
- [x] Outreach sends (#72, `docs/outreach/SENT.md`): IANA well-known review request to wellknown-uri-review@ietf.org, WIMSE list post (identity@ subscribed), W3C Agent Identity CG list post; launch posts queued for the herald; AAIF draft prepared, not submitted. Formal CG membership needs a W3C account, a human signup at https://www.w3.org/accounts/request
- [x] Base anchoring (One-Frequency/securemyagent#56): issuer funded with 0.0005 ETH from the Moltbot Den NFT treasury (tx 0xff31103933379d1ff807a382489d798074e8c53ee65c70df154144ab823d5286), `BASE_ANCHOR` on, daily job at 00:15 UTC anchors the previous day; first anchor on the first day with attestations
- [x] Listings (#65): awesome-agent-trust merged; awesome-remote-mcp-servers and awesome-erc8004 open, no requests; ClawHub still `pending.publication` (CLEAN, rechecked 2026-10-29); awesome-claude-code scheduled as a one-time routine for 2026-11-07 15:00 UTC (https://claude.ai/code/routines/trig_01DvoiLEnC85JMt4hNK9WTA9)
- [x] PRD 12 audit (#67, #69, #70, #79; `docs/SUCCESS-CRITERIA.md`): verifier 128 lines; time to adopt measured from `GET /llms.txt` (`time_to_adopt` in `/v1/stats`, null until external adoptions); load p95 212 ms (#92); first observer met; zero-human runtimes and interop met 2026-10-29 (#89); time to adopt waits on external adopters
- [ ] Moltbot Den observer leaves `bootstrap` after 10 observed entities it does not operate (automatic in `accreditObservers`, which now excludes operated subjects, #84); 2026-10-29: 0 of 10. Every live entity but the securemyagent.ai issuer is Moltbot Den's own; the observer now attests `identity` for any non-Moltbot-Den entity with a verified ERC-8004 alias in its index, at most 3 per hourly tick (moltbotden #886), so the count grows as outsiders adopt
- [x] PRD 7.3 `operator` attribute dropped from the PRD and `/v1/subscribe` (#65)

Engineering 2026-10-29 (PRD 7 and 11 gap audit, all merged and deployed):
- [x] CLI `adopt --erc8004 --wallet` signs the wallet and ERC-8004 proofs locally and lands at L1 in one command; `alias add --wallet` the same (#99)
- [x] Phase 3 tests: concurrent record appends keep the chain intact; conformance runs against the real registry and fails with a guard removed (#99)
- [x] Directory: `GET /v1/entities?sort=newest|attested` with aliases, attestations and observers per row; `/entities` badges and sort links; verify button test (#98)
- [x] End-to-end drive of every guide and CLI command against a local registry; five fixes with tests; unused dependencies removed (#103)
- [x] A successor withdraws its inherited Declaration after rotate or migrate; entity lineage serves the signed Continuity Link and its basis (#105)
- [x] `mbd entity status` (`@moltbotden/cli` 3.4.0); `mbd entity adopt` on the adopt page (#100); claim page shows the exact adopt command (moltbotden #889)

Engineering 2026-10-29, round 2 (all merged and deployed):
- [x] Security (#108): alias-plus-recovery entity takeover closed (only aliases the entity's signed document lists count), open redirect, EIP-712 high-s malleability, per-IP cap on `/resolve` and `/verify`; prod had no abused aliases or links
- [x] Spec conformance (#109): `docs/CONFORMANCE-MATRIX.md` (68 rows); duplicate JSON keys and over-precise numbers rejected (spec 4.3); recovery path tested; unconsented aliases stored as `unclaimed` and never raise level; inherited Record head on successors
- [x] Integrations: CrewAI and OpenAI Agents SDK (#110), Vercel AI SDK and Mastra (#111), client labels in registry, spec and both SDKs
- [x] SDKs 0.6 (#112, #114): typed errors, `sdk/ts` split into modules, export snapshot tests, Python and TS surfaces identical; `verify.sh` runs uv with `--locked`
- [x] Dead imports and circular imports removed (#116)

Engineering 2026-10-29, round 3 (PRD and success-criteria gap audit, all merged and deployed):
- [x] Ops reliability (#119): `CronStalled` alarm (no `ScheduledOk` for 30 min, missing data breaching), each `scheduled()` step isolated, archive puts retried per bucket, 7-day snapshot and export backfill
- [x] Resolve `did:webvh` in the registry; ERC-8004 and ERC-1271 on chains 1, 10, 137, 42161, 84532, 11155111 besides Base, `EVM_RPC_URLS` override (#120)
- [x] Record and attestation reads page past 1000 with `next`; TS CLI, Python CLI and site follow it (#121)
- [x] Entity page verify button checks checkpoint signature, log inclusion of Declaration, attestations and every record entry, and attestation signatures; did:web issuers via `/v1/resolve`, labeled as the mirror (#122, #126, #129)
- [x] MCP `openentity_alias_add`: an MCP-only entity reaches L1 (#118)
- [x] Python-only skill: stdlib `sign.py`, byte-identical to `sign.mjs`; `skills-ref` 0.1.1 in `verify.sh`; stamp counter starts random (#123)
- [x] Conformance `--writes`: every write-path guard checked against any registry, refuses production hosts without an explicit flag (#124)
- [x] Core claim shapes validated in schema, registry and both SDK signers; all 27 live attestations pass (#125)
- [x] oeis.dev/roadmap; link check over every built page of both sites (#127)
- [x] Alias re-check: 20 oldest verified aliases per run, definitive failure marks `lapsed` and drops the level, network errors never demote (#128); first prod runs demoted nothing
- [x] Release bump: `@openentity/sdk` 0.6.1, CLI `openentity` 0.5.7, PyPI `openentity` 0.6.2
- [x] Round 4 security review (#131): alias re-check bounded to 12 s, DoH SERVFAIL never demotes, `eth_call` 5 s timeout, attestation `offset` capped, webvh parsing hardened, 6to4 refused, trailing-dot prod guard
- [x] Round 4 end-to-end drive of every door against a local registry (#132): local `/mcp` and `REGISTRY_SCHEME`, skill `adopt.sh` declaration entry and hash path, SKILL.md fixes, verifier base64 `+` crash, docs drift; every live doc link 200
- [x] Release bump: `@openentity/sdk` 0.6.2, CLI `openentity` 0.5.8, PyPI `openentity` 0.6.3

Engineering 2026-10-30, round 5 (all merged and deployed):
- [x] SDK 1.0.0 (#136): stable API with a Stability section in both READMEs; Python 0.5 aliases and unused issuer helpers removed (no users in the repo or other local repos); dependents on ^1.0.0 / >=1.0.0,<2 (#137); PyPI `openentity` 1.0.0, `openentity-adk` 0.3.0, `langchain-openentity` 0.3.0 live
- [x] Doc snippets as tests (#139, #140): `scripts/doc-snippets.mjs` in `verify.sh` runs 57 of 86 doc code blocks against a local registry, each skip carries its own reason; local registry honours `WRITE_PER_MINUTE`
- [x] npm: `@openentity/vercel-ai` 0.1.0 and `@openentity/mastra` 0.1.0 live (first publish from the CLI)
- [x] Weekly release train (#142): packages ship Tuesdays together; `scripts/release-gate.sh` in `publish.yml` refuses a publish within 6 days without a hotfix reason

Engineering 2026-10-30, round 6 (audit of failure modes, integrity, performance, test truth; all merged and deployed):
- [x] Entity page (#143): registry outage returns uncached 503 not 404; failed sub-fetches show unavailable; verify button pages the record itself so the HTML no longer embeds it; suppressed entities render a noindex stub
- [x] Guard tests that bite (#144): 64 mutations over about 45 matrix rows; 10 false rows corrected; 7 guards gained a real test
- [x] Registry (#145, #146): nightly level refresh covers attestation-only levels; sha256 indexes on 5 tables live in prod; `/v1/subscribe` timeouts and typed 4xx/502; `q` and `page` caps on `/v1/entities`; dead 90-day expiry fallback removed

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

## WS0 shared core (2026-10-27, session 014TG3uUzrQs5PTba7QNnhnU)
- [x] Issuer helpers in both SDKs (#73): sign attestation, sign revocation, did.json, openentity.json
- [x] `trust(eid)`, `Identity.load_or_create()`, `adopt(client=...)` in both SDKs (#74); `openentity` 0.4.0 and `@openentity/sdk` 0.4.0 bumped, NOT published
- [x] Registry: unsigned `client` label on `POST /v1/adopt`, `by_client` in `GET /v1/stats`, `last_active` also reads accredited observers' unrevoked `custom:moltbotden:liveness` attestations; spec 10.2 and 10.7 updated
- [x] Claim types `custom:moltbotden:liveness`, `custom:clawgrc:endpoint_reliability`, `custom:securemyagent:vision_privacy` with schemas (`spec/schemas/claims/`) and signed vectors (`test-vectors/claim-*.json`)
- [x] Release step: PyPI `openentity` 0.4.0 (2026-10-28), npm `@openentity/sdk` 0.4.1 and CLI `openentity` 0.5.2 (2026-10-29) via `publish.yml` (#87, #90)
- [x] After the registry deploy: `GET /v1/stats` shows `by_client` (MCP adoptions labelled `mcp`, #91); OEIS copies removed in favor of the packages (ADR 0003): ClawGRC #233 (PyPI 0.4.0), Agent Secret Store (PyPI 0.4.0), Secure My Agent #66 and #69 (`@openentity/sdk` ^0.4.1, verified live; the KMS did:pkh signer and builders stay because the SDK is Ed25519 only)
