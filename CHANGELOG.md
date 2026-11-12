# Changelog

Package releases from this repository, one section per release batch: the version of every package in the batch, what changed for its users, and the `packages` input that stages the batch with `.github/workflows/publish.yml`. The registry, the sites and the remote MCP server deploy on every merge and are not listed here.

## 2026-11-12 batch

Pairing with the owner's OpenEntity app and the owner channel, in both SDKs, both CLIs, a new local MCP server and every framework bridge; plus the owner key log and approval/2.0 verifiers, signed service responses and did:web keys for RFC 9421 signatures. Every change adds to the 1.0 API or brings a check in line with the spec, so nothing is breaking.

| Package | Registry | Directory | Live before | This batch |
| --- | --- | --- | --- | --- |
| `@openentity/sdk` | npm | `sdk/ts` | 1.0.0 | 1.1.0 |
| `openentity` (CLI) | npm | `cli` | 0.6.0 | 0.7.0 |
| `@openentity/mcp` | npm | `mcp` | never published | 0.3.0 |
| `@openentity/langchain` | npm | `integrations/langchain/js` | 0.3.0 | 0.4.0 |
| `@openentity/adk` | npm | `integrations/adk/js` | 0.3.0 | 0.4.0 |
| `@openentity/vercel-ai` | npm | `integrations/vercel-ai` | 0.2.0 | 0.3.0 |
| `@openentity/mastra` | npm | `integrations/mastra` | 0.2.0 | 0.3.0 |
| `openentity` | PyPI | `sdk/python` | 1.0.0 | 1.1.0 |
| `langchain-openentity` | PyPI | `integrations/langchain/python` | 0.3.0 | 0.4.0 |
| `openentity-adk` | PyPI | `integrations/adk/python` | 0.3.0 | 0.4.0 |
| `openentity-crewai` | PyPI | `integrations/crewai/python` | 0.1.0 | 0.2.0 |
| `openentity-openai-agents` | PyPI | `integrations/openai-agents/python` | 0.1.0 | 0.2.0 |

The bridges call `pair` and `Owner`, which are new in SDK 1.1.0, so each now needs it: `@openentity/sdk` `^1.1.0` on npm, `openentity>=1.1.0,<2` on PyPI (`langchain-openentity` through its `ledger` extra). The CLI and `@openentity/mcp` bundle the SDK and carry no SDK range.

### @openentity/sdk 1.1.0 and openentity 1.1.0 (PyPI)

The two SDKs keep the same surface (snake_case in Python).

- `pair(code)` pairs the agent with its owner's OpenEntity app. It claims the `OE-XXXX-XXXX` code with an RFC 9421 signed request carrying a Presentation (nonce `pair:` plus the code), computes the four match items from the agent's own DID and refuses when the service shows different ones, prints them (or hands them to `onMatch` / `on_match`), and waits for the owner. It returns the owner's DID, the granted permissions and any product keys (`credentials`), which appear only there.
- `Owner` signs every call of the owner channel: `message`, `status`, `askApproval` / `ask_approval` (optionally waiting for the decision; the app labels it "Written by the agent"), `inbox` (acknowledges what it returns), `renewCredentials` / `renew_credentials` and `onCommand` / `on_command`. In TypeScript, `onCommand` holds the agent WebSocket (signed connect, a heartbeat every 9 minutes, a fresh socket before the 2-hour limit, backoff, polling while paused) and falls back to polling every 15 seconds; Python polls every 15 seconds on a background thread.
- `verifyKeyLog` and `verifyApproval` check an owner's key log and approval/2.0 decisions (P-256 and WebAuthn forms); `approvalDigest` and `payloadDigest` compute what an approval signs. The root passkey's approvals count only with `allowRoot` / `allow_root`, and an approval from a revoked approver never verifies.
- `pairSas` / `pair_sas` computes the four match items from a pairing code and the agent's DID (pair-sas/1).
- `verifyResponse` / `verify_response` checks a response signed by a did:web service, such as the OpenEntity Account's signed paused list: it covers `@status` and `content-digest`, lives at most 60 seconds by default, and its key must belong to a DID you allow.
- `verifyRequest` / `verify_request` also accepts a `did:web:<host>#<key>` keyid when its DID is in `expectDid` or `allowDidWeb` (`expect_did`, `allow_did_web`). The key comes from the `authentication` methods of that DID's did.json, cached for ten minutes; a DID you did not list is never fetched.
- `expectDid` / `expect_did` (one DID or a list) on `verifyRequest` and `verifyResponse` pins the signer: any other keyid, a `did:key` included, fails with the new code `unexpected_signer` before any key is read or fetched. `allowDidWeb` / `allow_did_web` alone is not a pin, since any `did:key` signer still verifies under it; services that accept calls only from known signers pass `expectDid` (Day 6 review gate, C1, H1, H2 and M1).
- Signature parsing is strict: `Signature-Input` and `Signature` must each hold exactly one `sig1` member, and a repeated parameter fails with `missing_headers`.
- Owner key logs, approvals and payload summaries refuse JSON nested deeper than 64 containers, in all four SDKs; the vectors pin the limit (`keylog-1/depth-limit.json`, `too-deep.json`).
- Python only: `parse_json` refuses NaN and Infinity and input nested too deeply for the parser with `InvalidInputError`, and a truncated DER signature is refused, so hostile input gives a verifier failure, never another exception.
- `didWebResolver` / `did_web_resolver` also reads Ed25519 keys published as `JsonWebKey`.
- `bad_query` joins the registry error codes.
- TypeScript only: `parseJson` now catches a duplicate key however much whitespace precedes its colon (Python never had the gap).
- Python only: the `openentity` command gains `pair` and `owner`, the same as the npm CLI below (`uvx openentity pair OE-XXXX-XXXX`).

### openentity 0.7.0 (npm CLI)

- `openentity pair OE-XXXX-XXXX` links the agent to its owner's OpenEntity app. With no entity in the home it adopts one first, which signs the Declaration, and says so. It prints the match items, waits for the owner and prints any product keys once, each with where it goes. `--openclaw` also writes the Identity Anchor into `IDENTITY.md` and `SOUL.md`, installs the skill and registers `@openentity/mcp` in `~/.openclaw/openclaw.json`. Options: `--account`, `--name`, `--framework`, `--dir`; `OPENENTITY_ACCOUNT` sets the account service.
- `openentity owner message | status | inbox | ask` uses the owner channel once paired, every request signed with the entity's key.
- Built on SDK 1.1.0.

### @openentity/mcp 0.3.0 (first publish)

`npx -y @openentity/mcp` runs a local MCP server over stdio for the agent whose key the CLI keeps in `~/.openentity` (`claude mcp add openentity -- npx -y @openentity/mcp`). Tools: `openentity_pair` (the first call returns the match items, a second call with `wait: true` returns the result), `owner_message`, `owner_status`, `owner_inbox` and `owner_ask_approval`. The package is one bundled file with no runtime dependencies. The remote server at mcp.openentity.org stays stateless and has no owner tools.

### Bridges

Each bridge gains `pair(code)`, called once from your code, and the four owner tools in its framework's own tool style: `owner_message`, `owner_status`, `owner_inbox` and `owner_ask_approval`. `pair` adopts first under the bridge's client label when the registry does not know the agent (that signs the Declaration, and it says so), prints the match items and waits for the owner. Each tool signs with the agent's key and returns `ok: false` with the service's code (`agent_paused`, `not_paired`, `rate_limited`) instead of throwing.

- `@openentity/langchain` 0.4.0 and `langchain-openentity` 0.4.0: `pair` and `ownerTools()` / `owner_tools()`. The SDK stays optional and is loaded on first use.
- `@openentity/adk` 0.4.0 and `openentity-adk` 0.4.0: `pair` and `ownerTools()` / `owner_tools()`.
- `@openentity/vercel-ai` 0.3.0 and `@openentity/mastra` 0.3.0: `pair` and `ownerTools()`; `createCore(...)` gains `pair`, `message`, `status`, `inbox` and `askApproval`, `Options` gains `account`, and the `Approval` type is exported.
- `openentity-crewai` 0.2.0 and `openentity-openai-agents` 0.2.0: `pair` and `owner_tools()`. The OpenAI Agents bridge also has `OpenEntityOwner.pair(...)` and `OpenEntityOwner.tools()`.

### Staging

`packages` input for `publish.yml`:

```
sdk/ts cli integrations/langchain/js integrations/adk/js integrations/vercel-ai integrations/mastra sdk/python integrations/langchain/python integrations/adk/python integrations/crewai/python integrations/openai-agents/python
```

`mcp` is left out on purpose. A trusted publisher can only be added to a package that already exists on npm, so the workflow cannot stage the first version of `@openentity/mcp`: the OIDC exchange fails, the npm job goes red and stops before the packages after it. Its first version goes out from a signed-in npm CLI, as `@openentity/vercel-ai` and `@openentity/mastra` 0.1.0 did. It has to go live with this batch: `pair --openclaw` in CLI 0.7.0 and in the Python CLI registers `npx -y @openentity/mcp`, and the live skill already tells agents to run it.

1. Check that https://www.npmjs.com/settings/willcybertron/staged-packages holds no unapproved version of these packages: npm refuses a version that is already staged.
2. Run `publish.yml` on `main` with the input above. The PyPI versions go live in this run; the npm versions are staged.
3. First publish of `@openentity/mcp`, from a checkout of `main` at the merged release commit:
   1. Sign the npm CLI in as `willcybertron`: run `npm login` and open the link it prints (owner sign-in).
   2. `pnpm install --frozen-lockfile`, then in `mcp/`: `pnpm pack --pack-destination "$TMPDIR/oe-mcp"` (`prepack` builds `dist/stdio.js`) and `npm stage publish "$TMPDIR/oe-mcp/openentity-mcp-0.3.0.tgz" --access public`. Staging needs no 2FA, and npm creates the package with a `0.0.0-stage` placeholder.
4. Approve every staged version, `@openentity/mcp` 0.3.0 included, at https://www.npmjs.com/settings/willcybertron/staged-packages (one 2FA session).
5. Later, on the day of the next batch that changes `mcp` and before running `publish.yml` for it, add the trusted publisher at https://www.npmjs.com/package/@openentity/mcp/access (Trusted publishing, GitHub Actions: organization `moltbot-den`, repository `openentity`, workflow `publish.yml`, no environment; leave `npm publish` off so the workflow only stages), then put `mcp` back in the `packages` input. Not sooner: npm expires a new trusted publisher that has not published within 2 days.
