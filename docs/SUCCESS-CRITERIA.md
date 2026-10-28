# PRD section 12 success criteria: measured evidence

Measured 2026-10-28 (UTC) from the live registry. Sources: `GET https://openentity.org/v1/stats`, `/v1/entities`, `/v1/observers`, `/v1/log/sth`, and read-only SQL through the RDS Data API (profile `openentity`, database `openentity`). No test entities were created for this audit.

Registry state at measurement: log tree size 52, 8 listed entities in `/v1/stats` (5 L0, 1 L1, 2 L2), 8 live attestations, 1 observer.

| Criterion | Measured value | Source | Met |
|---|---|---|---|
| Time to adopt: median under 60 s over the first 100 external adoptions | 0 external adoptions exist. The three real adopters are Moltbot Den's own (OptimusWill, Incredibot) and the securemyagent.ai issuer; the rest of the 8 listed are L0 probes and smoke tests. The registry also cannot measure the interval: the funnel starts at `GET /llms.txt`, which the site serves, and the registry keeps no per-visitor record (by design, PRD section 8 stores only hashed counters). The stamp `created` field is set by the client just before `POST /v1/adopt`, so it is not a funnel start either. | `SELECT eid, created, founding FROM entities`; `/v1/stats` | No |
| Zero-human adoption: three runtimes, transcripts in PRs | No transcript is committed. Runtimes that exist and could be run: the Moltbot Den bridge (`entity_adopt_openentity`) produced the two Founding Entities; the remote MCP server (`mcp.openentity.org`) and the CLI exist. Earlier MCP/CLI/Python runs were smoke tests on entities that are now withdrawn or suppressed, so they do not count. Missing: three distinct real, persistent agents adopting through three runtimes with captured transcripts. A throwaway adoption would not satisfy the criterion. | `SELECT name, withdrawn_at, suppressed FROM entities` | No |
| Independent verification: Python, read-only, 150 lines or fewer, checkpoint + 100 proofs + 100 signatures | `scripts/independent_verifier.py` exists and is runnable by a stranger, but is 188 lines (limit 150). Also, the log holds 52 leaves, so "100 random proofs" samples the whole log. | `wc -l scripts/independent_verifier.py` | No (line budget) |
| First observer: every Founding Entity has a current Moltbot Den attestation; one has `stage` at `agent` or above | Both Founding Entities (`founding = 1`) carry unrevoked Moltbot Den attestations (OptimusWill: `layer_scores`, `stage`, `identity`; Incredibot: `layer_scores`, `stage`, `identity`, `consistency`), all created 2026-10-25T23:06Z. Both `stage` attestations read `stage: agent` (profile `entity-framework/1.0`) and expire 2027-01-23, so they are current. | `SELECT issuer, subject, claim_type, revoked_at FROM attestations` | Yes |
| Interop: ERC-8004, `did:web`, `did:pkh` all reach L1 by alias | `did:pkh`: securemyagent.ai (`did:pkh:eip155:8453:0x62fe...`) is L1 through a verified `domain:did:web:securemyagent.ai` alias. OptimusWill and Incredibot (`did:pkh`) are L2. `did:web` as an entity: none listed. ERC-8004 agent: none listed. | `SELECT eid, type, value, status FROM aliases`; `/v1/entities` | Partly (did:pkh only) |
| Human funnel | One real confirmed subscriber recorded in `tasks/todo.md` (2026-10-27, PRs 58, 60, 61, 62). `GET /llms.txt` with a bot user agent returns 200, unchallenged. The Turnstile-required test is in the registry suite. Not re-driven here, because that needs a real signup. | `curl -A bot https://openentity.org/llms.txt`; `registry/test` | Yes, per tests and last real run |
| Truth: no typed counts, no em dashes, no banned claims; `verify` green | `scripts/verify.sh` fails on em dashes and runs on every push; counts come from `/v1/stats`. | `scripts/verify.sh` | Yes (enforced by verify) |
| Load: 100 adoptions/s for 60 s; p95 under 500 ms; every leaf incorporated within 10 min | 6000/6000 accepted at 100/s for 60 s. p95 was 1.2 s, above the 500 ms target. The 10-minute incorporation bound is enforced by the 10-minute checkpoint cron. Latest checkpoint timestamp 2026-10-28T03:00:13Z. | `tasks/todo.md` status; `/v1/log/sth` | No (p95) |

## Moltbot Den observer: still `bootstrap`

`did:web:moltbotden.com`, accredited 2026-10-25T22:44:23Z, `bootstrap: true`. It has attested 2 distinct entities (OptimusWill, Incredibot), both operated by Moltbot Den itself. `accreditObservers` clears the mark once an issuer has attested 10 distinct subjects and publishes `openentity:observer` in its well-known file. Today that is 2 of 10, and 0 of those 2 are entities it does not operate. Source: `GET /v1/observers`, `SELECT issuer, COUNT(DISTINCT subject) FROM attestations GROUP BY issuer`.

Note on the guard: the current rule counts every distinct subject, including ones the observer operates. The todo item wording ("observed entities it does not operate") is stricter than the code. Under the stricter reading the count is 0, so the mark stays regardless. Aligning the code with the stricter reading is a registry change that is not made here.

## Not buildable in registry only

- Time to adopt needs a funnel start (`GET /llms.txt`) that the site serves, and a visitor-to-adoption join that PRD section 8 forbids storing. A measurable form needs a PRD change (for example an opt-in `X-OE-Funnel` header carrying a client-side timestamp). Not built.
- Transcripts need real persistent agents adopting; no code change makes that true.
