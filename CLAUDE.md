# Open Entity

The Open Entity Identity Standard (spec id OEIS-1) and its home at openentity.org: the spec, the site, the registry, the `openentity` CLI, the remote MCP server, the skill, the SDKs. Public repo `moltbot-den/openentity`. Author and steward: Moltbot Den. Spec and skill are CC0-1.0; code is MIT.

Read first: `docs/PRD.md` (product scope), `spec/OEIS-1.md` (normative), `docs/RESEARCH.md` (evidence). The spec wins on object formats; the PRD wins on product scope; record any conflict under "Decisions" in the PR and fix the losing document in the same PR.

## Operating rules

1. Think before coding. State assumptions. Push back when a simpler approach exists. Stop when confused and name what is unclear.
2. Simplicity first. Minimum code that solves the problem, nothing speculative, no abstractions for single-use code.
3. Surgical changes. Touch only what you must. Match existing style.
4. Goal-driven execution. Define success criteria, loop until verified.
5. Use the model only for judgment calls (classification, drafting, summarization). Verification, canonicalization, signing, Merkle math, rate limiting and routing are code with tests.
6. Surface conflicts, do not average them. Pick one pattern, explain why, flag the other.
7. Read before you write: exports, callers, shared utilities.
8. Tests verify intent. Every guard in the spec (one Declaration per EID, record chain integrity, Declaration text-hash match, proof-of-work stamp, alias binding to the root EID, `seq` monotonicity, no Turnstile on agent endpoints) has a test that fails if the guard is removed.
9. Checkpoint after every significant step: done, verified, left.
10. Match the codebase's conventions even when you disagree; surface harmful ones instead of forking silently.
11. Fail loud. "Completed" is wrong if anything was skipped silently.
12. Decide as the senior engineer. Engineering, product, UX and security calls are yours; the only escalations are an action only the owner can take, new spend, and irreversible deletion of real data. Pick, state the decision in one line, execute, report.
13. Leave nothing behind. Test entities are withdrawn and marked, test emails purged from Customer.io, branches and worktrees removed, `tasks/todo.md` checked off, scratch files deleted, the working tree back on `main` and clean.
14. The owner is not an approval step. Never end with an options menu or a problem list for the owner to triage.

## Non-negotiables

- Nothing fails on GitHub. `scripts/verify.sh` is the single definition of a good commit and runs in the pre-push hook and in `test.yml`. Never `git push --no-verify`. New checks go into `verify.sh`, never straight into a workflow.
- Ship every PR yourself: `scripts/verify.sh` green, local review and fixes in the same commit, push, `gh pr create`, `gh pr checks <n> --watch`, `gh pr merge <n> --squash --delete-branch`, confirm `deploy.yml` (`wrangler deploy` on merge to `main`) is green, clean up.
- Conventional commits only. No Co-Authored-By lines and no AI attribution in commits or PRs.
- Truth from code. Every number on any public surface comes from `/v1/stats` or a generated manifest. Never type a count. No "coming soon", no "global standard", no "best", no user counts.
- Brand in prose: "Open Entity" (and "Moltbot Den", two words). "OEIS" appears only as the spec identifier `OEIS-1`. Identifiers (`openentity`, `org.openentity`, `X-OE-Stamp`) keep their forms.
- No em dashes anywhere: docs, code comments, UI copy, emails, posts. `verify.sh` fails on one.
- Agent endpoints never get a CAPTCHA, Turnstile, login, email, wallet or payment requirement. Only `/v1/subscribe` (the human form) has Turnstile. A test asserts it.
- Secrets live in the AWS Secrets Manager secret `openentity/app` (registry signing key, custody key, Customer.io credentials, Turnstile secret, origin header), never in code, tests, fixtures or committed env files. Test vectors use a published throwaway seed and say so.
- The registry is a mirror of signed objects, never their source of truth. Verifiers verify locally.

## Layout

pnpm workspaces: `spec/` (OEIS-1.md, schemas, declaration text and hash, claim-types.md), `site/` (Astro with Starlight; `server/` renders the dynamic pages), `site-dev/` (the oeis.dev hub, same design system, reference pages generated from the code), `registry/` (Hono on Node, PostgreSQL through the RDS Data API, S3; `schema.sql`), `infra/` (CDK: CloudFront, the one app Lambda, Aurora Serverless v2, S3, the per-minute cron), `cli/` (npm `openentity`), `mcp/` (remote MCP server at mcp.openentity.org, `server.json`), `skill/openentity/` (Agent Skills format), `sdk/ts/`, `sdk/python/` (PyPI `openentity`), `test-vectors/`, `scripts/` (`verify.sh`, load test, independent Python verifier), `docs/` (PRD, research, outreach drafts), `tasks/` (`todo.md`, `lessons.md`).

## Domains

`openentity.org` is canonical and the only domain in any URL the standard emits; `mcp.openentity.org` is the remote MCP server. `openentityidentitystandard.com` is a 301 of every path to `openentity.org`. `oeis.dev` is the developer and contribution hub (`site-dev/`), a third CloudFront distribution on the app Lambda tagged `x-oe-site: dev`; it never hosts the spec or the API (`/v1` and `/.well-known` 301 to openentity.org). The legacy redirect runs as the `redirects/` Worker on custom domains (Cloudflare free plan).

## Hosting

AWS account `openentity` (099705791378, us-east-1, profile `openentity`), paid from AWS credits; stack `OpenEntity` in `infra/`. Cloudflare has no budget beyond its free plan: it keeps DNS, the redirects Worker, Turnstile and Web Analytics only. Never put compute, storage or a paid feature on Cloudflare.

## Task tracking

`tasks/todo.md` holds the current phase plan with checkable items; check them off in the same PR and add a review section when a phase is done. After any correction from the owner, append a rule to `tasks/lessons.md` that prevents the same mistake.
