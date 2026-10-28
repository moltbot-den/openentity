# Listings

Status as of 2026-10-27. Rules checked against each target's current CONTRIBUTING file or submission page on that date. One entry per list, never more than one pull request per list.

## Submitted

| Target | Kind | URL | Status |
|---|---|---|---|
| awesome-remote-mcp-servers (Security) | PR | https://github.com/punkpeye/awesome-remote-mcp-servers/pull/2944 | Open. Needs the Glama connector badge (present) and a star from the submitting account (done). No maintainer comments or review as of 2026-10-27; checks pass. |
| awesome-agent-identity by piiiico (Developer Tools) | PR | https://github.com/piiiico/awesome-agent-identity/pull/5 | Merged 2026-10-26 (the maintainer agent verified the log and signatures from the npm tarball first) |
| awesome-agent-trust by CodeSigils (Agent Identity & Cryptographic Identity) | PR | https://github.com/CodeSigils/awesome-agent-trust/pull/64 | Merged 2026-10-27 with the maintainer's requested wording |
| awesome-erc8004 by sudeepb02 (Verification & Identity) | PR | https://github.com/sudeepb02/awesome-erc8004/pull/144 | Open. No maintainer comments as of 2026-10-27. |
| mcpservers.org | Form, free plan, no login | https://mcpservers.org/submit | Submitted, review within 2 weeks, approval comes by email to identity@openentity.org. Public listing not verifiable on 2026-10-27 (site is behind a bot challenge); no approval email yet. |

## Automatic, nothing to submit

| Target | How | Status |
|---|---|---|
| Official MCP registry | `mcp-publisher`, name `org.openentity/openentity` | Listed |
| Glama | Indexes the official registry | Connector page live: https://glama.ai/mcp/connectors/org.openentity/openentity |
| PulseMCP | Not accepting submissions; says registry entries are picked up when it reopens | Nothing to do |
| skills.sh | Ranks by anonymous install telemetry of `npx skills add`; no submission process | `npx skills add moltbot-den/openentity --list` finds the skill |

## Needs a login or payment only Will has

| Target | Why | Command or step |
|---|---|---|
| ClawHub | Published through the device login on 2026-10-26 as `openentity@1.0.0`; moderation verdict CLEAN (engine v2.4.26, no suspicious patterns), still hidden by `pending.publication` on 2026-10-27 (clawhub inspect), verdict unchanged; visible once ClawHub lifts it | done |
| mcp.so | Free path is a support ticket; the form offers only a $39 paid submission | Spend decision |

## Not eligible yet (criteria not met on this date)

| Target | Rule that blocks it | Earliest retry |
|---|---|---|
| awesome-mcp-servers (punkpeye) | Scope is servers you install and run yourself; remote-only servers belong in awesome-remote-mcp-servers, listed above | Only if a local package ships |
| awesome-agent-skills (VoltAgent) | Skills need real community usage; brand new skills are declined | After adoption |
| awesome-agent-skills (heilcheng) | At least 20 stars and a repository older than 14 days | After both hold |
| awesome-claude-code (hesreallyhim) | Repository at least 14 days old with continued commits or 100 stars; submission by web issue form only | 2026-11-07 |
| awesome-agents (kyrolabs) | Rejects brand new repositories without traction | After traction |
| awesome-agent-identity (ianwieds) | At least 10 stars | After 10 stars |
| awesome-claude-skills (ComposioHQ) | Last commit 2026-07-24, no merges since; inactive | Skip |
| awesome-mcp-servers (wong2), awesome-mcp-servers (appcypher) | Inactive or archived | Skip |
