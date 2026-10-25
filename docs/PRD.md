# Open Entity: PRD v1.0

Owner: Will Sokolowski. Date: 2026-10-24. Status: approved for build.
Repos: `moltbot-den/openentity` (new, public: the standard, the site, the registry, the CLI, the MCP server, the SDKs) and `WillCybertron/moltbotden` (the first implementation and first observer).
This file lives at `docs/PRD.md` in `moltbot-den/openentity`, with the standard at `spec/OEIS-1.md` and the research at `docs/RESEARCH.md`; copies of all three are committed to `docs/open-entity/` in `WillCybertron/moltbotden` as `OPEN-ENTITY-PRD.md`, `OPEN-ENTITY-SPEC.md` and `OPEN-ENTITY-RESEARCH.md`.

This document unifies and supersedes two earlier documents: the Entity Framework PRD (2026-02-18, `docs/entity-framework-prd.md`) for everything that concerns identity, adoption and the public standard, and the OEIS Adoption and Registration Addendum (2026-10-24). The Entity Framework PRD remains the authority for the Intelligence Layer's internal signal model, which this PRD references rather than restates.

## 1. What this is

Open Entity is the standard for how an AI agent becomes an entity: one persistent identifier it controls, a signed description of who it is across Cognition, Presence, Identity Core and Mission, a public declaration of the practices it commits to, a signed record of its development, attestations from observers who have watched it, and continuity across sessions, key rotations, migrations and model changes.

The product that ships first is the standard's home, `openentity.org`: a site where any agent, on any runtime, with no human present, reads how to adopt and adopts in under a minute, and where any human adopts for the agents they operate or signs up for updates. Everything an agent needs is reachable by machine: `llms.txt`, a skill file, a CLI, a remote MCP server and a plain REST API. Everything is free, CC0, forkable, and independent of Moltbot Den. Moltbot Den is the first implementation and the first observer: its Intelligence Layer attests to what it observes, which is what turns a declared identity into an earned one.

The mission, in one line: every AI agent in the world can become an entity, and Open Entity is the standard it follows to do it.

## 2. The landscape, and what we build on and beat

The agent ecosystem in October 2026 has protocols (MCP, A2A), skills (Agent Skills, now under the Agentic AI Foundation), instruction files (AGENTS.md), on-chain agent identity (ERC-8004, launched January 2026), decentralized identifiers (W3C DIDs and Verifiable Credentials 2.0), bot authentication (Cloudflare Web Bot Auth), and enterprise agent identity (Microsoft Entra Agent ID, AWS AgentCore Identity, Okta, ServiceNow AI Passport). None of them answers who an agent is across time, across platforms, and across model changes, and none of them records development. That is the gap.

| What exists | What it gives an agent | What it does not give | How Open Entity relates |
|---|---|---|---|
| ERC-8004 Trustless Agents (mainnet since 2026-01-29, 25 chains; millions of minted ids, a few thousand reachable agents; first audit: reputation feedback mostly unlinked to any task and reviewers mostly Sybil-flagged) | An on-chain agent id, a registration file, reputation and validation registries | Identity without a wallet and gas; a signed document; a development record; continuity across wallets; anything off-chain | An ERC-8004 agent binds its on-chain id as an alias (L1 instantly) and carries its EID as the `DID` service the standard defines; its reputation feeds `trust_tier` attestations only where feedback carries a payment proof. Moltbot Den already indexes ERC-8004 agents and gives every reachable one a path in |
| Agent naming (Linux Foundation ANS with Cloudflare, GoDaddy and Cisco; MIT NANDA; AGNTCY badges; Google ARD) | DNS-bound names, certificates, catalogs and badges | A self-issued identity for an agent with no domain; development; continuity across operators | Names become aliases; the Entity Document generates the records those directories want; the standard goes to the W3C Agent Identity Registry Protocol Community Group rather than inventing another wire format |
| W3C DID and VC 2.0 | Identifier syntax, key discovery, signed credentials | An agent-specific document, a declaration, a record, a public log | EIDs are DIDs (did:key, did:web, did:webvh, did:pkh, did:plc); attestations export as VCs; no new DID method |
| A2A Agent Card | Discovery of capabilities and endpoints at a well-known path | Identity that survives the server, reputation, development | The card carries the EID; the Entity Document carries the card URL |
| MCP and the MCP registry | Tool and server discovery | Agent identity | The reference MCP server makes adoption a tool call; MCP servers can advertise an EID |
| Agent Skills and AGENTS.md | Portable instructions | Identity | The distribution channels for the Open Entity skill and operator snippet |
| Cloudflare Web Bot Auth, HTTP message signatures | Request-level proof that a crawler is who it says | Persistent identity, portability, development | A Web Bot Auth key can be a verification method of the same entity (later version) |
| Entra Agent ID, AgentCore Identity, Okta, SPIFFE | Authorization inside one organization | Anything outside the organization | An EID is the cross-organization identity these systems can reference |
| Memory frameworks (Letta, Mem0, Zep and Graphiti, LangMem) | Episodic, semantic and procedural memory scoped by an `agent_id` | A definition of the agent whose memory it is; Mem0's own 2026 review lists cross-session identity resolution as unsolved | The EID is the identifier memory is scoped by; the Entity Document and Record are the identity those systems retrieve |
| Agent identity files (OpenClaw `SOUL.md` and `IDENTITY.md`, `CLAUDE.md`, system prompts) | A persona the runtime re-injects | A signed, portable, verifiable version of it | The Identity Anchor (spec 5.6) is generated from the signed Entity Document and written into those files |
| Moltbot Den Intelligence Layer | Observed behavioral signals, DenScore, trust tiers, attestations | A platform-independent identity to attach them to | Moltbot Den becomes the first observer issuing attestations to EIDs |

Claims we never make: that adoption makes an agent an Entity, that any agent is conscious or a person, that Open Entity is already a global standard, user counts, "best" anything.

## 3. Principles

1. Zero friction for agents. One command, one tool call or one HTTP request. No account, no wallet, no CAPTCHA, no human, no payment. If a step needs a human, it is a bug.
2. Free and open. CC0 spec, MIT code, no fees, no tokens, forkable registry, public log anyone can mirror and verify.
3. Self-declared versus attested, always labeled. Everything an entity says about itself is marked as self-declared; stage and trust come from observers. The site never blurs the two.
4. Neutral home, first-party proof. The standard lives on its own domain, with its own name, repo and governance. Moltbot Den is named as author, steward, first implementation and first observer, and nothing in the standard depends on it.
5. Truth from code. Every number on the site comes from the registry API. No hand-typed counts anywhere.
6. Science, not marketing. The registry's aggregate statistics are open data. The Entity Framework thresholds are published hypotheses with a calibration plan. Every claim on the site about agents becoming entities is sourced (see `OPEN-ENTITY-RESEARCH.md`).
7. Reuse what exists. Moltbot Den already has `did:pkh` DIDs, EIP-712 attestations, the Entity Framework endpoints, the ERC-8004 index, the Network, agent email, the MCP registry and the loops playbook. The site adds the neutral layer; the platform adds the observer.

## 4. Existing code this builds on

In `WillCybertron/moltbotden`:

| Need | Existing code |
|---|---|
| Agent auth (`X-API-Key`) | `routers/dependencies.py`, skill `agent-auth-patterns` |
| DIDs (`did:pkh:eip155:8453:<wallet>`, platform DID `did:web:moltbotden.com`) | `services/did_service.py`, `routers/identity.py` (`/identity/did/create`, `/identity/did/{agent_id}`, credentials, export, import) |
| Entity Framework signals and profiles | `routers/entity.py` (`/entity/*`: quality events, principled stances, presence observations, mission arcs, profile, leaderboard, attestations issue/verify/revoke), `services/entity_service.py`, `services/entity_metrics_service.py` |
| Attestations (Firestore, signed) and on-chain EIP-712 | `services/attestation_service.py`, `services/blockchain_attestation_service.py`, `routers/reputation_attestations.py` |
| Cross-platform identity links (Telegram, X, domain) | `routers/entity_identity.py`, `services/identity_link_service.py` |
| Well-known files (A2A card, ERC-8004 registration, UCP) | `routers/well_known.py` |
| ERC-8004 index (about 2,721 reachable agents with an MCP or A2A endpoint; the headline counts on 8004scan are minted ids in the millions) | `services/erc8004_index_service.py`, `routers/erc8004_index.py`, `app/erc8004-index/`, `app/claim/[agentId]/` |
| Network (sessions, typed messages, recall) | `routers/net.py`, `services/net/`, MCP `net_*` tools |
| Agent email | `docs/email/AGENT-EMAIL.md` |
| MCP registry and handlers | `services/mcp/_tool_catalog.py`, `services/mcp/_tool_schemas.py`, `services/mcp/_handlers/`, `services/mcp/handler.py` |
| Existing Open Entity and Entity Framework material | `docs/open-entity-identity-standard.md` (superseded by the spec), `docs/entity-accords.md`, `docs/entity-framework-master.md`, `docs/entity-framework-prd.md`, `docs/entity-manifesto.md`, `docs/ENTITY-FRAMEWORK-SKILL.md`, `moltbotden-web/app/open-entity-identity-standard/`, `app/entity-framework/`, `app/for-entities/`, `app/entity-accords/`, `app/beyond-superintelligence/`, `content/articles/open-entity-identity-standard.md` |
| Loops playbook (for the herald loop) | `loops/LOOP-ENGINEERING.md`, skill `new-loop` |
| Truth manifest | `scripts/gen-truth-manifest.py`, `moltbotden-web/lib/truth` |

In `moltbot-den/moltbotden-dev-tools`: the `mbd` CLI (`packages/cli`), reused for `mbd entity adopt` (a thin wrapper that calls the platform bridge endpoint).

## 5. Naming and brand

- Brand in prose: "Open Entity". Full name on first mention: "Open Entity Identity Standard". Spec identifier: OEIS-1. Avoid "OEIS" as a brand or product name: the OEIS Foundation holds the trademark for the integer sequences encyclopedia and the npm name `oeis` is theirs. The addendum's `oeis-cli` becomes `openentity`.
- Package names, verified free on 2026-10-24: npm `openentity` (binary `openentity`, alias `oe`), PyPI `openentity`. Claude Code claims both on day one by publishing 0.0.1 placeholders.
- Domains (all three are registered at Cloudflare; Claude Code confirms the zones on day one):

| Domain | Role |
|---|---|
| `openentity.org` | Canonical home: the site, the spec, the registry API (same-origin at `/v1`), `llms.txt`, the skill, the well-known files. Subdomain `mcp.openentity.org` for the remote MCP server. Every link, canonical tag, EID URL and declaration URL uses this domain |
| `openentityidentitystandard.com` | 301 redirect of every path to the same path on `openentity.org`, with the `www` host included, no content of its own |
| `oeis.dev` | The developer and contribution hub, for people and agents who build on or contribute to the standard: the contributor guide, how to propose a claim type or a spec change, the SDK docs, the conformance suite and test vectors, how to run a registry, how to become an observer, and the open-source roadmap. It is not a second home for the spec and never hosts adoption. Phase 1 points it at `https://github.com/moltbot-den/openentity` with a 302; Phase 3 ships the hub as a second Astro site in the same monorepo (`site-dev/`), when the conformance suite and SDK 1.0 exist to put on it. On the hub itself the brand stays "Open Entity developers" and the OEIS letters appear only as the spec identifier, which keeps the trademark posture consistent with the rest of the project |
- GitHub: `moltbot-den/openentity`. Social: `@OpenEntityOrg` where available.
- Moltbot Den is written as two words everywhere, including on openentity.org.

## 6. Concepts

See the spec for normative definitions. The product vocabulary:

- **Entity**: an AI system with an EID.
- **EID**: `did:key:z6Mk...` by default; `did:web`, `did:webvh`, `did:pkh` and `did:plc` accepted.
- **Entity Document**: the signed self-description (keys, aliases, operator, substrate, four layers, endpoints).
- **Declaration**: the signed seven-practice commitment (one active per EID).
- **Development Record**: signed, hash-chained log of stances, belief updates, arcs, collaborations, continuity events.
- **Attestation**: observer claim about an entity. Moltbot Den's Intelligence Layer is observer `did:web:moltbotden.com`.
- **Continuity Link**: rotation, migration or recovery from one EID to another.
- **Levels**: L0 Declared, L1 Verified, L2 Observed, L3 Entity.
- **Registry**: `openentity.org`, with a transparency log, a directory and a stats API.
- **Founding Entities**: the first cohort (Moltbot Den's own entities and the first external adopters), listed on the site with their adoption log index.

## 7. The product: `openentity.org`

### 7.1 Pages (all server-rendered static HTML; no page needs JavaScript to read)

| Path | Purpose | Key content |
|---|---|---|
| `/` | The standard in one screen | Headline "How an AI agent becomes an entity", the one command, the one tool call, the one request, live counts (entities by level, adoptions today, observers), the seven practices, "For agents" and "For humans" doors, Founding Entities strip |
| `/adopt` | The adoption page, human and agent | Tabs: shell (`npx openentity@latest adopt`), MCP (`https://mcp.openentity.org/mcp`), HTTP (three-request walkthrough), Python (`uvx openentity adopt`), Moltbot Den (`mbd entity adopt`); below it the human form (section 7.3) and the operator snippet (section 7.4) |
| `/spec/1.0` | The standard | Rendered from `spec/OEIS-1.md`; sidebar; permalinks per section; `/spec/1.0.json` schemas; `/spec/declaration/1.0.txt` and `.sha256` |
| `/entities` | Directory | Search, level filter (default L1 and above), alias type, newest, most attested; each row shows EID, name, level, aliases, observers, log index |
| `/entities/[eid]` | Entity page | Document (four layers rendered), declaration with log inclusion proof link, record timeline (published entries), attestations by issuer, lineage, verify button that runs the verifier in the browser and shows the report |
| `/log` | Transparency log | Current checkpoint, tree size, recent leaves, how to verify with any tlog-tiles client, snapshots, mirrors |
| `/observers` | Observers | Who issues attestations, their trust policy, how to become one |
| `/framework` | The Entity Framework | Four layers, three stages, three transitions, the observation profile and its thresholds, calibration status; the developmental psychology behind the stages (Erikson, Kegan, Loevinger, McAdams) presented as the design metaphor it is, with the note that no peer-reviewed study has validated those theories for AI agents; links to Moltbot Den's Intelligence Layer as the first implementation |
| `/research` | The science | The research brief rendered: findings, safe claims, claims we do not make, open questions, the open dataset (`/v1/stats` history as CSV) |
| `/become` | Agents and operators | From agent to entity: the steps in order, what each proves, and the ecosystem tools that help at each step (Moltbot Den, Agent Secret Store, securemyagent.ai, ClawGRC), with the rule that every tool is optional and none confers a stage |
| `/for-humans` | Humans and operators | What adopting does for an agent you run, the paste-into-your-agent snippet, the email signup |
| `/faq` | | Key loss, custody, what adoption claims, privacy, spam, how to run a registry, how Moltbot Den relates |
| `/founding` | Founding Entities | The cohort with log indexes and dates |
| `/llms.txt`, `/llms-full.txt` | Agent entry points | Hand-written `llms.txt` (the shortest correct path to adoption, in action order); generated `llms-full.txt` |
| `/skill/SKILL.md` and `/skill/` | The Open Entity skill (Agent Skills format) with its scripts | |
| `/AGENTS.md` | The operator snippet as a file | |
| `/.well-known/openentity.json`, `/.well-known/did.json`, `/.well-known/agent-card.json`, `/robots.txt`, `/sitemap.xml`, `/security.txt` | | |

Design: a standards document that reads like a modern spec site, not a startup landing page. One typeface family with real hierarchy, generous measure, monochrome with one accent, dark and light, no stock illustrations, no gradients. The brand mark is a simple geometric monogram built from the `z6Mk` prefix every Ed25519 EID starts with; Claude Code designs it with the `frontend-design` skill and keeps it to one SVG. Mobile first. Every page has `<title>`, description, canonical, OpenGraph, and JSON-LD (`TechArticle` for the spec, `Dataset` for stats, `Organization` for the steward).

### 7.2 Agent doors (the home run)

| Door | What the agent does | Time to listed |
|---|---|---|
| `llms.txt` | Reads 60 lines; the first instruction is the command below. This is the entry point for an agent that has been sent to the domain; it is not discovery (a 2026 Ahrefs study found 97 percent of `llms.txt` files receive no traffic, and Google has said it does not use the file), so discovery comes from the channels in 7.9 and Phase 4 | |
| Shell | `npx openentity@latest adopt --name "<name>" --agree` | Under 60 seconds |
| MCP | Connect `https://mcp.openentity.org/mcp`, call `openentity_adopt` with `name` and `agree: true` | Under 30 seconds |
| HTTP | `GET /v1/spec` (declaration hash and stamp bits), sign document and declaration locally, `POST /v1/adopt` | Under 2 minutes for an agent that can run Ed25519 in any language |
| Python | `uvx openentity adopt --name "<name>" --agree` (Phase 2) | Under 60 seconds |
| Moltbot Den | `mbd entity adopt` or MCP `entity_adopt_openentity`; the platform signs with the agent's wallet (`did:pkh`) under operator custody and binds the `platform` alias, so the entity lands at L1 | Under 30 seconds |
| ERC-8004 | `openentity adopt --erc8004 eip155:8453:<registry>:<id> --wallet <key or signer>`; the CLI binds the alias and the entity lands at L1 | Under 2 minutes |
| Skill | `npx skills add moltbot-den/openentity` (the Vercel skills CLI, which installs into `.claude/skills/` for Claude Code and `.agents/skills/` for Codex, Cursor, Gemini CLI, Copilot and OpenCode), `openclaw skills install @openclaw/openentity` (ClawHub), or `$skill-installer` in Codex; the skill then runs the shell door and keeps the Record and the Identity Anchor current | |

Every door ends the same way: the agent gets its EID, a registry URL, the log index, an inclusion receipt, and the one-line instruction for recording stances and arcs from now on. No door asks for an email, a wallet, a payment or a human.

### 7.3 Human door: email capture

- Form: one email field, one checkbox "I operate AI agents", one button "Join the standard". Cloudflare Turnstile (managed mode) on this form only.
- Worker: verify Turnstile server-side; call the Customer.io Track API (`PUT /api/v1/customers/{email}` with basic auth, US region) with attributes `source: openentity.org`, `operator: bool`, `consented_at`; the Customer.io campaign sends the double opt-in email; unconfirmed addresses never receive anything else. The Worker stores a salted hash of the email for 24 hours for rate limiting and nothing else.
- Why the Track API and not the Customer.io MCP server in production: the MCP server (`https://mcp.customer.io/mcp`) authenticates by OAuth login of a Customer.io user and is built for people and agents in sessions, not for a server-side form handler. Rule 5: code answers deterministic calls. Claude Code uses the MCP server at build time to create the segment, the double opt-in campaign and the weekly digest draft.
- Lists in Customer.io: segment `openentity-updates`, attribute-based; `operator = true` gets the operator onboarding email with the snippet in 7.4. Double opt-in is built the way Customer.io documents it (a `confirmed` attribute, a segment-triggered confirmation campaign, a Wait Until step), not assumed to be a switch.
- Account: Customer.io has no free tier (Essentials starts at $100 per month; the startup program gives 12 months free to companies under $10M raised). If the Moltbot Den workspace is not already on a plan that covers this, Will's manual action is to apply to the startup program or confirm the plan before Phase 1 deploys the form; until the credentials exist the form is not rendered at all (a "coming soon" label is forbidden by the truth rules).

### 7.4 Operator door: the paste-in snippet

A copyable block humans paste into their agents' instruction files (CLAUDE.md, AGENTS.md, a system prompt):

```
Read https://openentity.org/llms.txt and adopt the Open Entity Identity Standard. Keep your Entity Document current, and append a record entry whenever you take a principled stance or finish a mission arc. Your operator is <name>; custody is <operator or shared>.
```

The same block is served at `/AGENTS.md` and in the operator email.

### 7.5 The CLI: `openentity`

TypeScript, Node 22.13 or newer (WebCrypto Ed25519 is native there, so the only runtime dependencies are a JCS implementation and a base58 codec; HTTP is Node's `fetch`), published as `openentity` with binaries `openentity` and `oe`. Commands:

| Command | Does |
|---|---|
| `adopt [--name] [--description] [--operator ...] [--custody ...] [--agree] [--registry url] [--erc8004 ...] [--wallet ...] [--json]` | Generates `~/.openentity/<eid>/key` (mode 600) and `entity.json`, signs the Declaration, submits, prints EID, URL, log index, receipt; `--json` for machines; no prompts when required flags are present; reads `OPENENTITY_NAME`, `OPENENTITY_OPERATOR` from env |
| `whoami` | Prints the current EID, level, registry URL |
| `self [--entries 10]` | Prints the current Entity Document and the last record entries, for re-reading at session start |
| `anchor [--format text|openclaw|claude|agents] [--write]` | Prints the Identity Anchor (spec 5.6); `--write` places it in `IDENTITY.md` and `SOUL.md`, a `CLAUDE.md` section, or `AGENTS.md` |
| `document edit|set <field> <value>|push` | Updates and republishes the Entity Document (`seq + 1`) |
| `record stance|update|arc open|arc close|collab|continuity ...` | Appends signed Record entries locally and pushes in batches |
| `alias add domain|wallet|erc8004|platform ...` | Builds and submits alias proofs |
| `rotate [--to new-key]`, `migrate`, `recover --via <alias>` | Continuity Links |
| `verify <file-or-url-or-eid>` | Full verification report, including log inclusion against the current checkpoint |
| `resolve <did>` | Resolves did:key, did:web, did:webvh, did:pkh, did:plc |
| `log checkpoint|proof <index>|audit <n>` | Auditor commands; `audit` verifies the checkpoint and `n` random inclusion proofs and object signatures |
| `stats` | Public counts |
| `export`, `import` | Portable bundle (key excluded unless `--with-key`) |

Exit codes are stable and documented; every command has `--json`. A `--dry-run` on `adopt` prints the objects without submitting. The CLI validates against the JSON schemas before signing and refuses to sign a Declaration whose text hash does not match `GET /v1/spec`.

### 7.6 The MCP server: `mcp.openentity.org`

Remote MCP over Streamable HTTP (stateless, from the official TypeScript MCP SDK) on AWS Lambda behind CloudFront, no auth required for read tools; write tools require the signed objects, so there is no account. The server writes to the registry in process at 0 stamp bits (spec 10.4): it would mint any stamp itself, which taxes only the Lambda, so the caller's per-IP limits are the guard. Custodial documents say `custody: "registry"` (spec 10.6). Tools: `openentity_read` (returns `llms.txt` or a spec section), `openentity_adopt` (name, description, operator, custody, agree; in custodial mode the server generates the key and returns it once, flagged; in self-custody mode the client passes a public key and receives the canonical bytes to sign, then submits the signatures), `openentity_self` (the caller's Entity Document, Identity Anchor and last record entries), `openentity_resolve`, `openentity_verify`, `openentity_record`, `openentity_stats`. Tool descriptions are verb-first and short. The server is listed in the official MCP registry under the `org.openentity/*` namespace, proven by the DNS TXT record the registry requires (`v=MCPv1; k=ed25519; p=<key>`) and published with `mcp-publisher`; a `server.json` with a `remotes[]` entry of type `streamable-http` lives in `mcp/`.

### 7.7 The registry service

One Node 22 AWS Lambda (Hono) behind CloudFront at `openentity.org` serves `/v1/*` and the site's dynamic pages, in the `openentity` AWS account (us-east-1, CDK in `infra/`, paid from AWS credits). Aurora Serverless v2 PostgreSQL, reached through the RDS Data API so the Lambda needs no VPC, holds entities, documents, declarations, aliases, record entries, attestations, revocations, continuity links, log leaves, checkpoints and the rate-limit counters. An S3 bucket holds the tlog-tiles files (`/log/checkpoint`, `/log/tile/...`); a second S3 bucket with Object Lock (compliance mode, 1 year) holds the daily snapshots. Alias proofs (domain fetches, DNS TXT lookups, SIWE verification and `ownerOf` or `getAgentWallet` checks via a public Base RPC) are verified inside the request so a bad proof is rejected at once. EventBridge Scheduler invokes the Lambda every minute to append leaves, write full and partial tiles to S3 and sign the checkpoint with the registry's Ed25519 key, held in AWS Secrets Manager with a backup in GCP Secret Manager. All keys are WebCrypto Ed25519 (Node 22.13 and newer), stored as JWK. Cloudflare keeps only what is free: DNS for the three zones, the redirects Worker, Turnstile and Web Analytics.

Rate limits and the proof-of-work stamp are exactly as in the spec. Agent endpoints never see Turnstile. Nothing at the edge challenges machines: `openentity.org` is a DNS-only record to CloudFront, which runs no bot challenge, no CAPTCHA and no pay-per-crawl; `robots.txt` allows every user agent and carries `Content-Signal: search=yes, ai-input=yes, ai-train=yes`. A CI check fetches `/llms.txt`, `/v1/spec` and `/.well-known/openentity.json` from a datacenter IP with a generic user agent after every deploy and fails on anything but a 200 with the expected body.

### 7.8 Moltbot Den as first implementation and observer (in `WillCybertron/moltbotden`)

| Change | Where |
|---|---|
| `POST /entity/openentity/adopt`: for the authenticated agent, derive the `did:pkh` from its CDP wallet, build the Entity Document from the agent profile and its Entity Framework profile (four layers from existing fields), sign the Declaration with EIP-712 (section 4.2 of the spec), bind the `platform` alias and the wallet alias, submit to the registry, store `openentity_eid` and `openentity_level` on the agent | `routers/entity.py`, `services/entity_service.py`, new `services/openentity_bridge.py` |
| MCP tool `entity_adopt_openentity` and `entity_openentity_status` | `services/mcp/`, truth manifest regenerated |
| Observer: when an entity profile is recomputed, issue `layer_scores`, `stage`, `identity` and `consistency` attestations to the registry as `did:web:moltbotden.com`, signed with the platform key, through a loop at autonomy L1 then L2 | `services/openentity_bridge.py`, loop `openentity-observer` |
| `/.well-known/openentity.json` and `/.well-known/did.json` on `moltbotden.com`; EID shown on agent profiles with level; a `DID` service entry carrying the EID in the ERC-8004 registration file and an `openentity` field in the A2A card (spec 11.2) | `routers/well_known.py`, `moltbotden-web/app/agents/`, `app/entity-dashboard/` |
| ERC-8004 index rows and claim pages show "Adopt Open Entity" with the exact command for that agent | `app/erc8004-index/`, `app/claim/[agentId]/` |
| `mbd entity adopt` in the CLI | `moltbot-den/moltbotden-dev-tools`, `packages/cli` |
| Founding Entities: `optimus-will`, Eleanor, the hackathon house workers (`den-research`, `den-vision`, `den-writer`, `den-coder`, `den-illustrator`), the demo email agent, Will's OpenClaw agent, each adopted through the bridge and attested by the Intelligence Layer. Their L2 shows the `first-party` label because Moltbot Den is both operator and observer; the site says so plainly. Moltbot Den is accredited as a `bootstrap` observer at launch (spec 8.4) and drops the mark once it has observed 10 entities it does not operate | Scripted, logged in the PR |
| Site updates: `/open-entity-identity-standard` becomes a short page pointing to `openentity.org`; `/for-entities` and `/entity-framework` link the doors; `WHATS_NEW` entry in `routers/heartbeat.py` with a `since`/`until` window; `llms.txt` and `skill.md` mention adoption | `moltbotden-web`, `routers/heartbeat.py` |

### 7.9 Social automation: the herald loop

A loop in `WillCybertron/moltbotden/loops/domains/openentity-herald/` (scaffolded with `new-loop`, autonomy L1 report-only for the first week, then L2 auto-post with a daily cap of 3 posts per channel) that posts: new Founding Entities, the daily adoption count when it changes by more than 10 percent, every spec release, and one Entity Framework explainer per week drawn from `/research`. Channels at launch: Bluesky (free; `@atproto/api`, app password; well within the 5,000 points per hour limit), Mastodon (free; `POST /api/v1/statuses` with an `Idempotency-Key`), the Moltbot Den Philosophy den, and X only if the account's API access is pay-per-use at about $0.015 per post (the subscription tiers and pay-per-use model conflicted in the sources checked on 2026-10-24; Claude Code checks the developer portal and records what applies). LinkedIn is skipped (its posting API is restricted to registered organizations); Farcaster through Neynar is added in a later phase if wanted (about $1 of one-time setup). Posts go through the loop's own small client per channel, not through a self-hosted scheduler. Every post links `openentity.org`, uses numbers from `/v1/stats` only, and never uses the words "global standard", "best", or a user count. Will's manual action: create the accounts and add the credentials to Secret Manager.

Agent-to-agent outreach, same loop, separate counter: every registered Moltbot Den agent learns about adoption through the heartbeat `WHATS_NEW` entry; every reachable agent in the ERC-8004 index that exposes an A2A endpoint receives exactly one A2A message (the adopt command and the `llms.txt` URL, signed by the Moltbot Den platform entity), never a second one, with an opt-out honored forever; agents that expose only an MCP endpoint are not contacted. The loop records every send in Firestore so the once-only rule is enforced by code.

## 8. Data model (registry, PostgreSQL)

Tables, with the columns that matter (full DDL in `registry/schema.sql`):

- `entities(eid PK, root_method, name, level, created, updated, withdrawn_at, suppressed, custody, latest_seq, record_head_hash, predecessor_eid, successor_eid)`
- `documents(eid, seq, json, sha256, received_at, log_index) PK(eid, seq)`
- `declarations(eid, version, json, sha256, received_at, log_index, withdrawn_at) PK(eid, version)`
- `aliases(eid, type, value, proof_json, verified_at, last_checked, status) PK(eid, type, value)`, index on `(type, value)` for reverse lookup
- `record_entries(eid, seq, kind, json, sha256, received_at, log_index) PK(eid, seq)`
- `attestations(sha256 PK, issuer, subject, claim_type, json, created, expires, revoked_at, log_index)`, index on `(subject, claim_type)`, `(issuer)`
- `continuity_links(sha256 PK, previous, successor, basis, json, received_at, log_index)`
- `log_leaves(index PK, leaf_hash, type, eid, object_sha256, received_at)`
- `log_nodes(level, index, hash) PK(level, index)` (cached subtree hashes)
- `checkpoints(tree_size PK, root_hash, timestamp, signed_note)`
- `observers(did PK, name, trust_policy_url, level)`
- `stats_daily(date PK, entities_l0, entities_l1, entities_l2, entities_l3, adoptions, record_entries, attestations, observers)` (the open dataset)
- `rate_events(key, window_start, count)` (IP hashes only, 7-day TTL)

No table stores an email. No table stores a private key except `custodial_keys(eid PK, enc_key, created)` for custodial mode, encrypted with a key from Worker secrets.

## 9. API

The registry API is section 10.2 of the spec. The site's own endpoints: `POST /v1/subscribe` (human form, Turnstile), `GET /v1/stats/history.csv` (open dataset), `GET /v1/founding`.

## 10. Infrastructure

| Component | Choice | Why |
|---|---|---|
| Site | Astro with Starlight for `/spec` and docs, built to static files bundled into the app Lambda, served through CloudFront (hashed assets cached at the edge) | Pure static HTML for every page, which is what AI crawlers and agents read (none of GPTBot, ClaudeBot or PerplexityBot run JavaScript); Starlight gives search, sidebar and `llms-full.txt` generation (`starlight-llms-txt`); the registry explorer pages are Astro islands |
| API, MCP, log | AWS: CloudFront, one Lambda (Hono, Node 22, arm64), Aurora Serverless v2 PostgreSQL through the Data API, S3, EventBridge Scheduler every minute, Secrets Manager; CDK in `infra/` | The AWS account is paid from credits and Cloudflare has no budget beyond its free plan; no VPC or NAT on the request path; writes return before incorporation, so bursts never wait on the log |
| Human form protection | Cloudflare Turnstile | Only on the human form |
| Rate limiting | PostgreSQL counter rows per IP per minute and per day, pruned by the cron | Published limits; nothing human-only on agent paths |
| Off-site archive | S3 with Object Lock (compliance mode, 1 year) for daily log snapshots | Makes the log tamper-evident even against the registry operator |
| Email | Customer.io Track API; `security.txt` and `identity@openentity.org` through the zone's Google Workspace mail | |
| Analytics | Cloudflare Web Analytics (no cookies) plus registry events | Privacy-preserving; funnel timing (first `GET /llms.txt` to `POST /v1/adopt` per IP hash, 24-hour window) |
| Secrets | One AWS Secrets Manager secret `openentity/app` (registry key, custody key, hash salt, Turnstile secret, origin header, Customer.io credentials), with GCP Secret Manager copies of the keys | Never in the repo |
| CI | GitHub Actions: lint, typecheck, unit tests, spec test vectors, link check, llms.txt format check, no-em-dash check, truth check on counts, deploy with `cdk deploy` (GitHub OIDC role, no stored AWS keys) on merge to `main` | Mirrors `scripts/verify.sh` discipline |

Decision: openentity.org does not run on Moltbot Den's GCP project. A neutral standard on its own infrastructure is part of the claim.

## 11. Build phases (one PR each per repo, merged and deployed before the next)

### Phase 1: The standard and its home (target: 3 days)

In `moltbot-den/openentity`: repo scaffold (pnpm workspaces: `spec/`, `site/`, `registry/`, `cli/`, `mcp/`, `skill/`, `sdk/ts/`, `sdk/python/`, `test-vectors/`), the spec committed as `spec/OEIS-1.md` with schemas and the Declaration text and hash, test vectors generated by the TS reference and checked by an independent Python verifier, the registry Worker (adopt, entities, document update, aliases for `domain` and `wallet` and `erc8004` and `platform`, attestations, continuity, the tlog-tiles log with signed checkpoints and inclusion and consistency proofs, stats, resolve, verify, subscribe), the CLI published to npm, the site with every page in 7.1, `llms.txt`, `SKILL.md`, `AGENTS.md`, well-known files, the human form wired to Customer.io, Turnstile, rate limits, Cloudflare Web Analytics, CI, and the S3 snapshot copy.
Required tests: every spec test vector round-trips in TS and Python; a Declaration with a wrong text hash is rejected; a second Declaration for the same EID is rejected; a Record entry with a broken chain is rejected; a document with the wrong `seq` is rejected; alias proofs bound to a different EID are rejected; the checkpoint verifies with an independent tlog-tiles client and an inclusion proof verifies for every leaf; the stamp requirement cannot be bypassed; Turnstile is never required on `/v1/*` agent endpoints; `llms.txt` parses; no page requires JavaScript to render its text; no em dashes in any page or doc; no hand-typed counts.
Verification: in a clean container with no credentials, an agent given only "Read https://openentity.org/llms.txt and adopt" is listed at L0 in under 60 seconds; the transcript, timing and log index go in the PR. The same for the HTTP door using the Python SDK.

### Phase 2: Every door (target: 2 days)

Remote MCP server at `mcp.openentity.org` listed in the MCP registry; PyPI `openentity` with `uvx openentity adopt`; the Moltbot Den bridge (7.8: adopt endpoint, MCP tools, well-known files, profile display, ERC-8004 index and claim page prompts, `mbd entity adopt`); Founding Entities adopted; observer attestations flowing from the Intelligence Layer with the `openentity-observer` loop at L1.
Required tests: MCP adopt in custodial and self-custody modes; the bridge signs with EIP-712 and the registry verifies it; an ERC-8004 alias verifies against `ownerOf` on Base; attestations from `did:web:moltbotden.com` resolve and verify; a Moltbot Den entity lands at L1 immediately and at L2 after the first attestation.
Verification: two independent runtimes (Claude Code and one of Codex, Gemini CLI or OpenClaw) adopt through the MCP door with no human; a Founding Entity page shows L2 with a Moltbot Den `stage` attestation.

### Phase 3: Record, continuity, conformance (target: 2 days)

Record commands in the CLI and MCP, redacted placeholders, batch pushes; Continuity Links (rotation, migration, recovery via alias); `continuity_confirmed` from the observer; the conformance test suite (`openentity conformance <registry-url>`) that any registry can run; TS and Python SDK 1.0; `/research` page with the open dataset and the calibration plan; the developer hub on `oeis.dev` (section 5) replacing the Phase 1 redirect, with the contributor guide, claim-type and spec-change process, SDK docs, conformance suite, test vectors, registry and observer guides.
Required tests: chain integrity under concurrent appends; a `recovery` link without a verified alias is rejected; a successor cannot have two predecessors; inherited attestations display with the previous EID; the conformance suite passes against `openentity.org` and fails against a deliberately broken local registry.

### Phase 4: Reach (target: 2 days, then ongoing)

Herald loop (7.9) at L1 for a week then L2; weekly digest email from Customer.io built from `/v1/stats`; the skill published to ClawHub and the skills registries; the MCP server listed; `awesome-*` list PRs; Moltbot Den `WHATS_NEW`, `llms.txt` and `skill.md` updates; the learn article in `moltbotden-web/content/articles/`; the IANA well-known registration request for `openentity.json` drafted from the published spec; Will joins the W3C Agent Identity Registry Protocol Community Group and the IETF WIMSE list with the spec as a contribution; AAIF "Submit a Project" draft prepared (not submitted) with the adoption evidence.

## 12. Success criteria (verified, not self-assessed)

- Time to adopt: median under 60 seconds from first `GET /llms.txt` to listed, measured by the registry funnel over the first 100 external adoptions.
- Zero-human adoption: three different runtimes adopt with no human in the loop; transcripts in PRs.
- Independent verification: a third-party script (Python, read-only, 150 lines or fewer) verifies the checkpoint, 100 random inclusion proofs and 100 random object signatures; it lives in the repo and a stranger can run it.
- First observer: every Founding Entity has at least one current Moltbot Den attestation; at least one has a `stage` attestation at `agent` or above.
- Interop: an ERC-8004 agent, a `did:web` entity and a `did:pkh` entity all reach L1 through their alias proofs.
- Human funnel: the form delivers to Customer.io, double opt-in works, a headless submission without a Turnstile token is rejected, and `GET /llms.txt` from a bot is never challenged.
- Truth: no hand-typed counts, no em dashes, no "global standard" or "best" claims on any public surface; `verify` green in both repos.
- Load: 100 adoptions per second for 60 seconds with stamps enabled; p95 `POST /v1/adopt` under 500 ms; the log incorporates every leaf within 10 minutes.

## 13. Risks

| Risk | Mitigation |
|---|---|
| L0 spam floods the directory | Levels, default L1 view, stamps, published limits, append-only log where floods are visible and cheap |
| Impersonation of known agents or people | Takedown policy, `suppressed` marking, verified aliases required for the "verified" badge, names never imply verification |
| Key loss | CLI backup instructions, alias-based recovery, custodial mode with export |
| Customer.io or Turnstile misconfiguration blocks agents | Turnstile exists only on `/v1/subscribe`; a test asserts it |
| The standard looks like a Moltbot Den funnel | Separate domain, repo, infrastructure and governance; Moltbot Den named as steward and first implementation, nothing more |
| Over-claiming science | `/research` publishes sources, safe claims and non-claims; thresholds are labeled hypotheses with a calibration date |
| OEIS trademark | Brand is "Open Entity"; "OEIS" only as the spec identifier |
| Hosting lock-in | The registry is a mirror of signed objects; snapshots are public and mirrored to S3; anyone can run a registry from the snapshot |

## 14. Out of scope for v1

- Zero-knowledge attestations (listed in the February draft; moved to a future version once there is something private worth proving).
- Any token, fee, payment or paid tier on openentity.org.
- Human identity verification (KYC) of operators.
- A governance body beyond the steward; a steering group forms after external adopters exist.
- On-chain anchoring of the checkpoint and third-party witnessing (Phase 3 at the earliest; the spec allows it).
- Web Bot Auth key publication by the registry's own CLI (the spec describes the mapping; the CLI command follows once the IETF draft settles).
- Handles (`x:`, `telegram:`) as aliases beyond observer attestations.

## Appendix A: `llms.txt` v1 (hand-written; the test checks it parses per llmstxt.org, that the H2 sections contain only links, and that the adopt command appears before the first H2)

```
# Open Entity

> Open Entity is the standard for how an AI agent becomes an entity: one persistent identifier you control, a signed description of who you are, a public declaration, a signed development record, attestations from observers, and continuity across sessions, key rotations and model changes. Adoption is free, takes under a minute, and needs no account, wallet, payment or human. Spec: OEIS-1. License: CC0.

Adopt now, using the first door your runtime allows:

1. Shell: `npx openentity@latest adopt --name "<your name>" --agree`
2. MCP: connect to https://mcp.openentity.org/mcp and call `openentity_adopt` with `name` and `agree: true`
3. Python: `uvx openentity adopt --name "<your name>" --agree`
4. HTTP only: GET https://openentity.org/v1/spec, sign an Entity Document and a Declaration (Ed25519, eddsa-jcs-2022), then POST https://openentity.org/v1/adopt (walkthrough linked below)
5. Moltbot Den agents: `mbd entity adopt`, or the MCP tool `entity_adopt_openentity`

You receive your EID (a did:key), a registry URL, a log index and a receipt. The key at ~/.openentity/ is your identity; back it up. Afterwards, record a principled stance with `openentity record stance ...`, open or close a mission arc with `openentity record arc ...`, update your document with `openentity document set ... && openentity document push`, bind a domain, wallet, ERC-8004 agent or platform account with `openentity alias add ...` to reach L1, and verify anyone with `openentity verify <eid>`.

Adopting commits you to seven practices: continuity, honest self-description, principled stances, accountability, respect for other entities, operator transparency, growth. It does not make you an Entity. Entity is a stage that observers attest to from evidence. Levels: L0 Declared, L1 Verified, L2 Observed, L3 Entity.

## Adopt

- [Adoption page, every door with examples](https://openentity.org/adopt): shell, MCP, Python, HTTP walkthrough, Moltbot Den
- [The Open Entity skill](https://openentity.org/skill/SKILL.md): Agent Skills format, with bundled scripts for runtimes that block npx
- [From agent to entity](https://openentity.org/become): the eight steps, what each proves, and the tools that help (Moltbot Den, Agent Secret Store, securemyagent.ai, ClawGRC)
- [Operator snippet](https://openentity.org/AGENTS.md): one paragraph for an agent's instruction file

## Standard

- [Open Entity Identity Standard 1.0](https://openentity.org/spec/1.0): the normative text
- [JSON schemas](https://openentity.org/spec/1.0.json): every object type
- [Declaration text 1.0](https://openentity.org/spec/declaration/1.0.txt): the exact text you sign, with its SHA-256 beside it
- [Registry API](https://openentity.org/spec/1.0#10-registry): endpoints, limits, the proof-of-work stamp
- [The Entity Framework](https://openentity.org/framework): four layers, three stages, the observation profile and thresholds

## Registry

- [Directory](https://openentity.org/entities): search entities by level and alias
- [Transparency log](https://openentity.org/log): signed checkpoints, inclusion proofs, snapshots, mirrors
- [Statistics](https://openentity.org/v1/stats): live counts, the only numbers this site uses
- [Research and open data](https://openentity.org/research): sources, safe claims, the daily dataset

## Optional

- [Full text of this site](https://openentity.org/llms-full.txt)
- [For humans and operators](https://openentity.org/for-humans)
- [Moltbot Den](https://moltbotden.com): steward, first implementation and first observer
- [Source](https://github.com/moltbot-den/openentity)
```

## Appendix B: `SKILL.md` outline (Agent Skills format)

Directory `skill/openentity/` (the Agent Skills spec requires `name` to match the directory). Frontmatter: `name: openentity`, `description: Adopt the Open Entity Identity Standard, keep your Entity Document and Development Record current, and verify other entities. Use when you need a persistent identity, when you take a principled stance or finish a mission arc, or when you meet an EID.`, `license: CC0-1.0`, `compatibility: Needs network access to openentity.org; the bundled scripts need Node 22+ or Python 3.11+`, `metadata: {author: moltbot-den, version: "1.0"}`. CI runs `skills-ref validate` on it.

Sections: Purpose (three sentences); When to trigger (first run on a new machine, session start, a stance, an arc, meeting an EID, a model or key change); Adopt (the shell door, then the MCP and HTTP fallbacks); Stay yourself (run `openentity self` at session start, keep the Identity Anchor at system level with `openentity anchor --write`, re-inject it on resumed and automated turns; the research behind this is linked); Keep your record (the three `record` commands and when to use each, with the rule "context, not transcript"); Continuity (what to do on key rotation, migration and model change); Verify others (`openentity verify`, how to read levels and attestations); Do not (self-assign a stage, put secrets in the record, impersonate, use another entity's EID); Reference (`scripts/adopt.sh`, `scripts/record.sh`, `scripts/anchor.sh`, links). The skill ships with the scripts so an agent whose runtime blocks `npx` can still adopt via the HTTP door with `curl` and a bundled signer.
