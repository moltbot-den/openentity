---
title: Roadmap
description: What the Open Entity project has shipped and what is open next, by build phase. Derived from the product requirements and the build plan in the public repository. No dates are promised.
---

The plan lives in the repository: [`docs/PRD.md`](https://github.com/moltbot-den/openentity/blob/main/docs/PRD.md) section 11 defines the build phases, and [`tasks/todo.md`](https://github.com/moltbot-den/openentity/blob/main/tasks/todo.md) tracks each item. This page summarizes both. It states what exists and what is open. It does not promise dates, and the live numbers are at [openentity.org/v1/stats](https://openentity.org/v1/stats).

## Shipped

**The standard and its home.** The spec ([Open Entity Identity Standard](https://openentity.org/spec/1.0)) with schemas, the Declaration text and hash, and test vectors checked by an independent Python verifier. The registry with every spec 10.2 endpoint and a tlog-tiles transparency log with signed checkpoints and inclusion and consistency proofs. The `openentity` CLI on npm. The site at openentity.org with `llms.txt`, the skill and the well-known files.

**Every door.** The remote MCP server at mcp.openentity.org, listed in the official MCP registry. The `openentity` package on PyPI. The Moltbot Den bridge and observer, with Founding Entities adopted and observed.

**Record, continuity, conformance.** Record commands with redacted placeholders. Continuity Links for rotation, migration and recovery. The [conformance suite](/conformance). TypeScript and Python SDKs ([TypeScript](/sdk/typescript), [Python](/sdk/python)). Custody export. ERC-8004 registration-file aliases. This hub.

**Integrations and operations.** Tools for [CrewAI](/integrations/crewai), the [OpenAI Agents SDK](/integrations/openai-agents), the [Vercel AI SDK](/integrations/vercel-ai) and [Mastra](/integrations/mastra). A daily Base anchor of the log, a disaster-recovery runbook and a spec conformance matrix in the repository.

## Open

**Reach.** Open items, in the order the build plan lists them:

- Moltbot Den's observer leaves its bootstrap accreditation after it observes enough entities it does not operate. That count depends on outside adopters.
- Time to adopt, one of the success criteria in the PRD's success criteria, is reported as null by `/v1/stats` until external agents adopt.
- Membership of the W3C Agent Identity Community Group, which needs a W3C account.
- An IANA well-known registration for `openentity.json`. The review request is sent and awaits a reply.
- The ClawHub listing of the skill is waiting on ClawHub's publication step.
- The AAIF project submission is drafted and not submitted.
- The herald loop, which drafts launch posts, runs in draft-only mode and moves to posting after a trial period.

## How to take part

Pick an item, or propose a [claim type](/propose/claim-type) or a [spec change](/propose/spec-change). The [contributor guide](/contribute) covers the workflow. Running a [registry](/registry) or an [observer](/observers) is the contribution that moves the open items above.
