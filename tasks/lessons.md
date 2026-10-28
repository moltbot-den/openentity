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
