# Lessons

## 2026-10-24: Terse replies, one ask at a time
The kickoff report listed seven manual actions at once and the peer-message reply ran long. Will: "stop being so verbose ... ask me one single thing at a time".
Rule: keep replies short; when Will must act, ask for exactly one action per message, the most blocking first.

- The account is on the Workers Free plan: D1 allows 100,000 rows written per day across every database on the account, and each adopt writes about 25 rows (tables plus index entries). The two 6,000-adopt load runs on 2026-10-24 wrote 308,587 rows to the preview database and blocked D1 writes for the rest of that UTC day. Before any load test, compute adopts x 25 and keep it under the remaining daily quota, or run it on Workers Paid.
- Hosting is AWS (account `openentity`, paid from credits), not Cloudflare. The owner did not write the Cloudflare-first architecture in the PRD and has no Cloudflare budget beyond the free plan. Before building on any vendor, check which accounts carry credits and how sibling projects (securemyagent `infra/`) deploy, and ask nothing: match them.
- Never mint a proof-of-work stamp server side on a request path. The MCP door minted two 20-bit stamps per adopt (about 15 s each on Lambda), timed out after the adopt committed, and lost the generated key. A stamp the registry computes for itself protects nothing; in-process doors write at 0 bits under the caller's per-IP limits.
- Keep a test entity's key until its withdrawal returns 200. A cleanup `rm` chained after a failing withdraw deleted the only key and left an orphan that had to be suppressed by hand. Delete keys in a separate step, after checking the status.
- A load test in the production AWS account shares the account-level Lambda concurrency pool (1000) with openentity.org. On 2026-10-25 a load run used all of it and the live site returned ConcurrentInvocationLimitExceeded. Cap the load stack's function with reserved concurrency (300) and watch the live site return 200 during any run.

## 2026-10-26: No per-agent summaries
While eight parallel agents finished, each completion got a multi-bullet chat summary. Will: "don't send these long as summaries just do work and kick ass".
Rule: while agents run, acknowledge a finished one in one line at most and keep working; one short report at the very end.
- Worktree agents cannot remove their own worktree; the lead removes each one (`git worktree remove --force`, `git branch -D`) when the agent reports.

## 2026-10-27: Five-line reports, links for approvals
The end-of-run report ran to a dozen bullets and said "approve on npmjs.com" with no link. Will: "STOP BEING SO FUCKING VERBOSE ... give me the fucking link."
Rule: final report is five lines at most; every owner action is a clickable URL. Machine-wide rule in `~/.claude/CLAUDE.md` ("Replies: short").

## 2026-10-27: Nothing is left for Will
The session ended by listing open items as "left for you" and calling the session done while the plan still had a dozen open items. Will: "I'm not doing shit. Ever. Agents can do it."
Rule: every open item in `tasks/todo.md` is agent work, with the method written next to it (Claude in Chrome for signups, existing wallets for funding, SES for mail). Never write an "owner" section or tell Will a task is his. "Done" means the todo list has no open item that work in this session could close.

## 2026-10-28: Fuzz probes reached production
Five `did:key` entities named like `[]`, `${PATH}` and `/tmp/pp-fuzz/probe` were adopted on openentity.org on 2026-10-27 and showed up in the first weekly digest. They were marked `suppressed`.
Rule: fuzz and probe runs point at a local registry (`pnpm --filter @openentity/registry local`) or OpenEntityLoad, never openentity.org.

## 2026-10-28: Check what a DNS record serves before replacing it
The mailbox lane replaced the apex Google Workspace MX with SES for one address, which would have bounced every other address on the domain.
Rule: before changing MX or any shared record, list what it serves today and keep every address working (here: a catch-all receipt rule).

## 2026-10-28: Account signups are a human step
Agents may not create accounts or enter passwords on third-party sites, even with the owner's authorization. Plan signups as one human step with the exact URL, and have the agent do everything after it in the signed-in session.

## 2026-10-29: Never idle behind an approval
The lead parked work while waiting on two npm 2FA approvals. Will: "I have no idea why you would ever just be setting there not working on something".
Rule: an owner approval blocks only the step that needs it. Start every dependent task right away on the unreleased version (local tarball or workspace) and merge the moment the release lands.
- Fuzz entities (`%n`, `name`, `0`) were adopted on openentity.org again on 2026-10-28 09:03Z, after the 2026-10-28 lesson. They are suppressed. Probes go to `pnpm --filter @openentity/registry local` only.

## 2026-10-30: Release as a planned batch, not per merge
SDK, CLI and integration versions went out every few minutes on 2026-10-29 and 2026-10-30 (sdk 0.6.0, 0.6.1, 0.6.2, 1.0.0 in a day), each needing an owner approval, and an out-of-order approval left `latest` on an older version. Will: "It looks super rookie if we have changes we know that we're gonna be doing."
Rule: a release is a planned batch on any day, judged not gated (CLAUDE.md "Releases"); feature PRs never bump versions. Will rejected hard calendar gates.

- Packages (`openentity` on npm and PyPI, `@openentity/sdk`, the CLI, the skill) ship as a planned batch, never as a side effect of a merge (CLAUDE.md "Releases"). (2026-10-29)
