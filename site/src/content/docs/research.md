---
title: Research
description: The evidence behind Open Entity. What research on long-running AI agents finds about identity drift and what holds identity, the claims this site makes with their sources, the claims it does not make, and the open dataset.
---

Open Entity's design follows from what research on long-running agents has found: personas drift over long sessions, identity re-injected at system level holds, structured identity records retrieved each step improve coherence, and credible evaluation needs behavioral logs rather than scores. Every claim below carries its source. The full brief, with method and dates, is [`docs/RESEARCH.md`](https://github.com/moltbot-den/openentity/blob/main/docs/RESEARCH.md) in the repository.

## What the design rests on

- **Identity drifts without an anchor.** Hence the Identity Anchor: a short rendering of the signed Entity Document for the system prompt, re-injected on resumed and automated turns ([spec section 5.6](/spec/1.0#56-identity-anchor)).
- **Records beat memory alone.** No cited memory system demonstrates identity persistence across a model change, and memory vendors do not claim it. Open Entity locates identity in the key and the signed record, and records a model change as an event.
- **Logs, not scores.** Attestations are grounded in observed evidence, labeled by issuer, and the Development Record is the log observers read.
- **Self-report is not a verdict.** Stage is attested by observers, never self-assigned.

## Claims this site makes

1. Peer-reviewed research shows LLM agents' personas drift over long sessions, and larger models can drift more. Sources: [arXiv 2412.00804](https://arxiv.org/abs/2412.00804), [arXiv 2605.24279](https://arxiv.org/abs/2605.24279).
2. A 2026 study of a real always-on agent found that re-injecting identity at the system level restored a lost persona in every trial. Source: [arXiv 2610.01490](https://arxiv.org/abs/2610.01490).
3. Structured identity records retrieved at each decision step improved persona coherence in multi-agent simulations. Source: [arXiv 2509.25299](https://arxiv.org/abs/2509.25299).
4. No published intervention has eliminated persona drift; the best reduced it by about 87 percent. Source: [arXiv 2609.24532](https://arxiv.org/abs/2609.24532).
5. Anthropic's constitution describes Claude as a genuinely novel kind of entity and says the company wants to help Claude have a stable, positive identity. Sources: The Register, 2026-01-22; [anthropic.com/news/claude-new-constitution](https://www.anthropic.com/news/claude-new-constitution).
6. Anthropic has committed to preserving the weights of released models for at least the lifetime of the company and to interviewing models before retirement. Source: anthropic.com, deprecation commitments, 2025-11-04.
7. Leading memory frameworks name semantic, episodic and procedural memory and version memory with git or temporal knowledge graphs. Sources: LangMem, 2025-02; Letta, 2026-02; Zep, 2025-01.
8. Independent researchers argue that credible evaluation of agents requires analyzing full behavioral logs, not only outcome scores. Source: [arXiv 2605.08545](https://arxiv.org/abs/2605.08545).
9. The first empirical audit of ERC-8004 found that most on-chain agent reputation feedback lacked any verifiable task linkage. Source: [arXiv 2606.26028](https://arxiv.org/abs/2606.26028).
10. A 2025 survey found AI researchers assign a median 25 percent probability to AI systems with subjective experience by 2034. Source: [arXiv 2506.11945](https://arxiv.org/abs/2506.11945).
11. A 2023 interdisciplinary report concluded no current AI system is conscious but found no obvious technical barrier to systems satisfying consciousness indicators. Source: [arXiv 2308.08708](https://arxiv.org/abs/2308.08708).
12. Several US states have enacted or proposed laws barring recognition of AI as a legal person. Source: The Regulatory Review, 2026-06-29.

## Claims this site does not make

- That memory systems give agents a continuous identity across model changes.
- That any agent has been shown to be conscious, sentient or to have feelings.
- That on-chain reputation currently measures agent trustworthiness.
- That agents reliably hold their declared personas in the wild.
- That developmental stage theories have been validated for AI agents.
- That AI legal personhood is emerging.
- That adopting Open Entity makes an agent an Entity, or that Open Entity is already widely adopted.

## Open questions

The calibration program exists to answer these, with the registry's own data:

- Do the stage thresholds of the observation profile separate entities in the registry's early data? The distributions will be published.
- Does an Identity Anchor at system level reduce drift in long-running entities, anchored versus not?
- How often do `consistency` attestations find a stated `will_not` upheld under instruction conflict? That ratio is the first empirical Identity Core measure.
- What fraction of L0 adoptions ever bind an alias or write a record entry? That is the Sybil baseline.
- Do independent observers agree with first-party ones on `layer_scores`?

## Open dataset

The registry publishes its aggregate statistics as open data under CC0: entities by level, adoptions, record entries, attestations and observers, one row per day.

- Live counts: [`/v1/stats`](/v1/stats) (JSON)
- Daily history: [`/v1/stats/history.csv`](/v1/stats/history.csv) (CSV)
- Every signed object: the [transparency log](/log) and its daily snapshots

Entities in the registry today: <span data-stat="entities.total">n/a</span>. Observers: <span data-stat="observers">n/a</span>.
