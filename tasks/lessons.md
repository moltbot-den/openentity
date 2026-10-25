# Lessons

## 2026-10-24: Terse replies, one ask at a time
The kickoff report listed seven manual actions at once and the peer-message reply ran long. Will: "stop being so verbose ... ask me one single thing at a time".
Rule: keep replies short; when Will must act, ask for exactly one action per message, the most blocking first.

- The account is on the Workers Free plan: D1 allows 100,000 rows written per day across every database on the account, and each adopt writes about 25 rows (tables plus index entries). The two 6,000-adopt load runs on 2026-10-24 wrote 308,587 rows to the preview database and blocked D1 writes for the rest of that UTC day. Before any load test, compute adopts x 25 and keep it under the remaining daily quota, or run it on Workers Paid.
- Hosting is AWS (account `openentity`, paid from credits), not Cloudflare. The owner did not write the Cloudflare-first architecture in the PRD and has no Cloudflare budget beyond the free plan. Before building on any vendor, check which accounts carry credits and how sibling projects (securemyagent `infra/`) deploy, and ask nothing: match them.
