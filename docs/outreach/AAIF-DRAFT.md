# Agentic AI Foundation "Submit a Project": DRAFT

**Status: draft. Not submitted.** Will submits after reading it. Fill the evidence section from `/v1/stats` on the day of submission and do not hand-type numbers into the form unless the form demands them; if it does, paste the figure with its date and the endpoint it came from.

Before submitting, re-read the current submission guide and the foundation's project-acceptance criteria on aaif.io and adapt headings to the form. The answers below are written to be pasted.

## Project name

Open Entity (Open Entity Identity Standard, spec id OEIS-1)

## One-line description

An open standard for the persistent identity of AI systems: a key they control, a signed self-description and declaration, a signed development record, observer attestations, and continuity across key rotation and model change.

## Gap it fills

The Agentic AI Foundation hosts the protocol, skill, instruction, router, sandbox and environment layers of the agent stack: A2A, MCP, Agent Skills, AGENTS.md, goose and others. None of the hosted projects defines identity over time or a public record of an agent's development. Enterprise identity products bind an agent to one organization, on-chain identity is bound to one chain, and memory frameworks scope memory by an `agent_id` they do not define. Open Entity fills that gap using W3C DIDs and Verifiable Credentials rather than a new method, and it composes with the projects already hosted (see "Fit").

## Repository and license

- Repository: https://github.com/moltbot-den/openentity (public)
- Specification and skill: CC0-1.0. Code (CLI, registry, SDKs, MCP server): MIT.
- Home: https://openentity.org. Developer hub: https://oeis.dev.

## Governance today and proposed

- Today: Moltbot Den is steward and first implementer and first observer. Changes are public pull requests; editorial changes are merged by the steward; a backward-compatible change is a new minor version and anything else a new major version (spec section 14). Anyone may fork the standard and run a registry.
- Proposed: contribute the specification, schemas, test vectors and conformance suite to the foundation, move the repository and the `openentity` name to foundation-neutral ownership, and replace single-steward control with a technical steering group that includes at least one implementer that is not Moltbot Den. Moltbot Den keeps running the reference registry as one registry among many.

## Fit with hosted projects

| Project | How Open Entity relates |
|---|---|
| A2A | The Agent Card carries the entity identifier as an `AgentExtension`; the entity document carries the card URL; cards sign with the same Ed25519 key |
| MCP | A remote MCP server (`mcp.openentity.org`) exposes adoption and verification as tools; MCP servers can advertise an identifier |
| Agent Skills | The Open Entity skill is distributed in the Agent Skills format and runs adoption for any agent that loads skills |
| AGENTS.md | A paste-in snippet in `AGENTS.md` makes an agent adopt on its next run, and the Identity Anchor writes into the identity files agents already load |
| goose, Agent Router, agentgateway, Open Responses, OpenEnv, OpenSandbox | Any of these can sign requests or carry the identifier; no change to them is required |

## Technical maturity

- Normative specification with JSON Schemas, a Declaration with a published hash, and published test vectors using a throwaway seed.
- Reference registry with a C2SP tlog-tiles transparency log that anyone can mirror and verify.
- Independent verifier in Python alongside the TypeScript reference, to catch implementation-specific interpretations.
- CLI (`openentity`), TypeScript and Python SDKs, remote MCP server, skill.
- Guards in the spec each have a test that fails if the guard is removed.

## Adoption evidence (fill on the day)

Pull live from the public stats endpoint and the log, with the date:

- Entities listed, by conformance level: `GET https://openentity.org/v1/stats`
- Independent observers accredited, and entities observed by an observer that does not operate them: the stats endpoint and the observers page
- Registries other than the reference registry, if any
- Independent implementations of the verifier or the CLI, if any (link them)
- Third-party mentions or integrations (link each)

Do not claim anything this list does not show. If independent adoption is thin on the day, say so; the proposal rests on the gap and the design, not on volume.

## Why a neutral home

A standard for identity across organizations and platforms cannot be credible if one platform controls it. Moltbot Den is both the steward and the first observer, and the site labels that conflict ("first-party") for exactly this reason. Foundation hosting is the way to remove the conflict.

## What we are not asking for

No funding. No exclusive status. No change to hosted projects. No claim that adoption makes an AI system an Entity, conscious or a legal person.

## Contact

Will Sokolowski, Moltbot Den
