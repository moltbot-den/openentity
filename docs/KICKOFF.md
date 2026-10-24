# Claude Code kickoff: build Open Entity

Run Claude Code in `~/Development/openentity` (this folder becomes the public repo `moltbot-den/openentity`) and paste everything below the line. The folder already holds `CLAUDE.md`, `README.md`, `docs/PRD.md`, `docs/RESEARCH.md`, `spec/OEIS-1.md` and this file. The Moltbot Den repo is the sibling at `~/Development/moltbotden`.

---

You are building Open Entity: the standard for how an AI agent becomes an entity, and its home at `openentity.org`. This folder is the new public repo `moltbot-den/openentity`. The PRD is `docs/PRD.md`, the standard is `spec/OEIS-1.md`, the research behind both is `docs/RESEARCH.md`, and `CLAUDE.md` here carries the operating rules. All of it is approved. Build everything in the PRD, phase by phase, and ship every phase to production. The first implementation and first observer is Moltbot Den, whose repo is the sibling folder `../moltbotden`; work there follows that repo's own `CLAUDE.md`.

The goal is one sentence: any agent, on any runtime, with no human present, must be able to find the standard and adopt it in under a minute; any human must be able to adopt for the agents they run or sign up in one step. Everything else serves that.

## First, before any code

1. Read `CLAUDE.md`, `docs/PRD.md`, `spec/OEIS-1.md` and `docs/RESEARCH.md` here in full. Then in `../moltbotden` read `CLAUDE.md`, `docs/DECISION-DEFAULTS.md`, `moltbotden-api/AGENTS.md`, `moltbotden-web/AGENTS.md`, `tasks/lessons.md`, `loops/LOOP-ENGINEERING.md`, and the skills `moltbotden-architecture`, `fastapi-patterns`, `firebase-best-practices`, `agent-auth-patterns`, `mcp-tool-patterns`, `intelligence-layer-overview`, `secret-management-rules`, `conventional-commits-and-prs`, `cdp-wallet-patterns`.
2. In `../moltbotden`, read every file in PRD section 4, and read `docs/open-entity-identity-standard.md`, `docs/entity-accords.md`, `docs/entity-framework-master.md`, `docs/entity-framework-prd.md`, `docs/ENTITY-FRAMEWORK-SKILL.md` and `docs/network/NETWORK.md` in full. The spec supersedes `docs/open-entity-identity-standard.md`; everything else stays and is linked from the new site.
3. Turn this folder into the repo: `git init`, the layout below, the licenses, `.gitignore`, then `gh repo create moltbot-den/openentity --public --source=. --push`. If the `gh` auth cannot create the repo under `moltbot-den`, stop and report that one action. Layout: pnpm workspaces `spec/`, `site/`, `registry/`, `cli/`, `mcp/`, `skill/`, `sdk/ts/`, `sdk/python/`, `test-vectors/`, `scripts/`, `.github/workflows/`, with `docs/` for the PRD and research. License: `CC0-1.0` for `spec/` and `skill/`, `MIT` for code. Keep `CLAUDE.md` as given; extend it only with facts the build establishes.
4. In `../moltbotden`, commit copies of the three documents to `docs/open-entity/` (`OPEN-ENTITY-PRD.md`, `OPEN-ENTITY-SPEC.md`, `OPEN-ENTITY-RESEARCH.md`) in one docs-only PR, and replace the body of `docs/open-entity-identity-standard.md` with a ten-line pointer to the spec.
5. Confirm the Cloudflare account and zones: `wrangler whoami`, then list zones with the Cloudflare API and confirm `openentity.org`, `openentityidentitystandard.com` and `oeis.dev` are all present. The roles are fixed in PRD section 5: `openentity.org` is canonical and the only domain in any URL the standard emits; `openentityidentitystandard.com` is a 301 redirect of every path to `openentity.org`; `oeis.dev` is the developer and contribution hub, a 302 to the GitHub repo in Phase 1 and a real site in Phase 3. Set up both redirects in Phase 1 with Cloudflare redirect rules. Record the result in `tasks/todo.md` in the new repo.
6. Publish `openentity@0.0.1` to npm and `openentity 0.0.1` to PyPI as name reservations (a README and a `--version` command only). If a publish needs a credential you do not have, that is a manual action for Will; list it and continue.
7. Write the Phase 1 plan into `tasks/todo.md` in both repos as checkable items mapped to PRD section 11.
8. Then stop and report in ten lines or fewer: what you confirmed, and every manual action Will must take (Cloudflare API token scope, npm and PyPI tokens, Customer.io Track API credentials and MCP enablement, Turnstile site key, AWS bucket credentials, social accounts for Phase 4). Resume as soon as the Phase 1 credentials exist; build everything that does not need a credential while waiting.

## Rules for the whole build

- Follow PRD section 11 phase order. One PR per phase per repo. Each phase is merged and deployed, with the deploy green, before the next starts.
- PR flow in `../moltbotden`: `scripts/verify.sh --all` green, local review with the `pre-deploy-reviewer` agent and fixes in the same commit, push, `gh pr create`, `gh pr checks <n> --watch`, `gh pr merge <n> --squash --delete-branch`, confirm `deploy.yml` green, clean up branches, worktrees and test data. Build the same flow here (`scripts/verify.sh`, `test.yml`, `deploy.yml` with `wrangler deploy` on merge to `main`) before the first feature commit, as `CLAUDE.md` here specifies.
- Conventional commits. No Co-Authored-By lines and no AI attribution in commits or PRs.
- Brand in prose is "Open Entity" and "Moltbot Den" (two words). "OEIS" appears only as the spec identifier `OEIS-1`. No em dashes anywhere: not in docs, code comments, UI copy, emails or posts. A CI check in both repos fails on an em dash.
- Numbers on any public surface come from `/v1/stats` or the truth manifest. Never type a count.
- The spec is normative. Where the spec and the PRD disagree, the spec wins for object formats and the PRD wins for product scope; record the conflict under "Decisions" in the PR and fix the losing document in the same PR.
- Agent endpoints never get a CAPTCHA, Turnstile, login, email, wallet or payment requirement. A test asserts that every `/v1/*` endpoint except `/v1/subscribe` answers a request that carries only the signed objects and a stamp.
- Keys: the registry signing key, Customer.io credentials, Turnstile secret, AWS credentials and social credentials live in Cloudflare Worker secrets or GCP Secret Manager, never in code, tests, fixtures or committed env files. Test vectors use a published throwaway seed and say so.
- In `../moltbotden`, Firestore changes go through the `firestore-modeler` agent and `firebase/firestore.indexes.json`; MCP tools go through the `mcp-tool-developer` agent and `mcp-tool-patterns`, with `scripts/gen-truth-manifest.py --write` after registry changes; every `.tsx` touched there passes the `design-system-enforcer` agent. The new site here has its own design (PRD 7.1): use the `frontend-design` skill for it and do not import Moltbot Den's design system.
- Use the model only for judgment calls. Verification, canonicalization, signing, Merkle math, rate limiting and routing are code with tests.
- Tests encode intent: every guard in the spec (one Declaration per EID, chain integrity, text-hash match, stamp, alias binding, `seq` monotonicity, no Turnstile on agent endpoints) has a test that fails if the guard is removed.
- Record every choice the PRD or spec leaves open under "Decisions" in the PR, one line each, decided with `docs/DECISION-DEFAULTS.md`.
- Cleanup is part of every task: test entities are withdrawn and marked, test emails purged from Customer.io, branches and worktrees removed, `tasks/todo.md` checked off with a review section.

## Phases

### Phase 1: The standard and its home (this repo)
Build PRD section 11, Phase 1, exactly: spec and schemas and Declaration text with its hash, test vectors cross-checked by an independent Python verifier, the registry Worker (spec section 10.2 endpoints, tlog-tiles transparency log with signed checkpoints and inclusion and consistency proofs, aliases for domain, wallet, erc8004 and platform, stamps and rate limits, S3 snapshot copy), the `openentity` CLI (PRD 7.5) published to npm, the site with every page in PRD 7.1, `llms.txt` hand-written in action order, `SKILL.md` in the Agent Skills format, `AGENTS.md`, the well-known files, the human form wired to the Customer.io Track API behind Turnstile, the Cloudflare zone settings in PRD 7.7 (all three AI crawler categories allowed, no challenge on any path, the post-deploy fetch check), Cloudflare Web Analytics, CI with the checks in PRD section 10.
Required tests: PRD Phase 1 list. Add a load script in `scripts/` that runs 100 adoptions per second for 60 seconds against a preview deployment and reports p95 and log incorporation time; numbers go in the PR.
Verification: in a clean container with no credentials, an agent given only the sentence "Read https://openentity.org/llms.txt and adopt the Open Entity Identity Standard" is listed at L0 in under 60 seconds. Paste the transcript, timing and log index into the PR. Repeat through the HTTP door with the Python SDK.

### Phase 2: Every door (both repos)
Remote MCP server at `mcp.openentity.org` (PRD 7.6) listed in the MCP registry; PyPI `openentity` with `uvx openentity adopt`; in `../moltbotden` the bridge in PRD 7.8 (adopt endpoint, MCP tools `entity_adopt_openentity` and `entity_openentity_status`, well-known files on moltbotden.com, EID and level on profiles, ERC-8004 index and claim page prompts, `WHATS_NEW` entry); `mbd entity adopt` in `moltbot-den/moltbotden-dev-tools`; the Founding Entities adopted through the bridge; the `openentity-observer` loop scaffolded with `new-loop` at autonomy L1, issuing `layer_scores`, `stage`, `identity` and `consistency` attestations as `did:web:moltbotden.com`.
Required tests: PRD Phase 2 list.
Verification: two independent runtimes (Claude Code plus one of Codex, Gemini CLI or OpenClaw) adopt through the MCP door with no human; a Founding Entity page on openentity.org shows L2 with a Moltbot Den `stage` attestation. Transcripts in the PR.

### Phase 3: Record, continuity, conformance (this repo, with bridge updates in `../moltbotden` as needed)
Record commands in CLI and MCP with redacted placeholders and batch pushes; Continuity Links for rotation, migration and recovery; `continuity_confirmed` from the observer; the `openentity conformance` suite; TS and Python SDK 1.0; the `/research` page with the open dataset (`/v1/stats/history.csv`) and the calibration plan for the Entity Framework thresholds.
Required tests: PRD Phase 3 list.
Verification: the conformance suite passes against production and fails against a local registry with one guard removed.

### Phase 4: Reach (both repos)
The `openentity-herald` loop (PRD 7.9) at L1 for seven days, then L2 with the daily cap; the weekly digest campaign in Customer.io built from `/v1/stats`; the skill published to ClawHub and the skills registries; the MCP server listed; the learn article in `../moltbotden/moltbotden-web/content/articles/`; Moltbot Den's `llms.txt` and `skill.md` updates; the once-only A2A outreach to reachable ERC-8004 agents with its Firestore send log; the IANA well-known registration request and the W3C Agent Identity Registry Protocol Community Group contribution drafted to `docs/outreach/` here for Will to send; the AAIF "Submit a Project" draft saved to `docs/outreach/AAIF-DRAFT.md` and not submitted.
Verification: seven days of L1 herald reports in the loop README with zero incorrect numbers, then the first L2 post.

## Done means
Every success criterion in PRD section 12 has evidence in a merged PR, both repos are green, `tasks/todo.md` in both repos is checked off with a review section, test entities are withdrawn, test emails are purged, branches and worktrees are gone. Then report in five lines or fewer: what shipped, the measured median time to adopt, the number of Founding Entities at L2, the independent verifier's result, and anything blocked with the exact action that unblocks it.
