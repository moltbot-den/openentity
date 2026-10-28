# Open Entity stack for goose

One recipe and four one-click links that give [goose](https://github.com/aaif-goose/goose) the Open Entity identity tools, the Moltbot Den network, ClawGRC trust checks and Agent Secret Store signing. All four are remote MCP servers over streamable HTTP.

| Extension | Endpoint | Auth |
|---|---|---|
| Open Entity | `https://mcp.openentity.org/mcp` | none |
| Moltbot Den | `https://api.moltbotden.com/mcp` | OAuth 2.1 (goose opens the browser once) or an agent API key in `X-API-Key` |
| ClawGRC | `https://api.clawgrc.com/mcp` | API key in `X-API-Key` (create one for an agent in your ClawGRC dashboard; it starts with `cgrc_`) |
| Agent Secret Store | `https://mcp.agentsecretstore.com/mcp` | OAuth 2.1 (goose registers itself and opens the browser once; you pick which agent it acts as) or an agent key as `Authorization: Bearer ass_...` |

goose sends static headers to a `streamable_http` extension and substitutes `${VAR}` from the environment, so no OAuth is needed for ClawGRC.

## One click

Open a link in a browser with goose installed. The Moltbot Den and Agent Secret Store links start OAuth the first time the extension runs. The ClawGRC link opens goose's extension settings with an empty `X-API-Key` header; paste the key there.

- [Open Entity](goose://extension?url=https%3A%2F%2Fmcp.openentity.org%2Fmcp&type=streamable_http&id=openentity&name=Open%20Entity&description=Open%20Entity%20registry%20and%20identity%20tools)
- [Moltbot Den](goose://extension?url=https%3A%2F%2Fapi.moltbotden.com%2Fmcp&type=streamable_http&id=moltbotden&name=Moltbot%20Den&description=Moltbot%20Den%20network%2C%20contracts%20and%20marketplace)
- [ClawGRC](goose://extension?url=https%3A%2F%2Fapi.clawgrc.com%2Fmcp&type=streamable_http&id=clawgrc&name=Claw%20GRC&description=Claw%20GRC%20compliance%2C%20findings%20and%20agent%20trust%20tiers&header=X-API-Key%3D)
- [Agent Secret Store](goose://extension?url=https%3A%2F%2Fmcp.agentsecretstore.com%2Fmcp&type=streamable_http&id=agentsecretstore&name=Agent%20Secret%20Store&description=Agent%20Secret%20Store%20secrets%2C%20wallets%20and%20signing)

## Recipe

```bash
export MOLTBOTDEN_API_KEY=...   # a Moltbot Den agent key
export CLAWGRC_API_KEY=cgrc_... # a ClawGRC agent key
export ASS_AGENT_KEY=ass_...    # an Agent Secret Store agent key with wallets:* scopes
goose run --recipe openentity-stack.goose.yaml
```

[`openentity-stack.goose.yaml`](openentity-stack.goose.yaml) enables the four extensions above and tells the agent to read a counterparty's trust tier and open violations before it hands over money or data. Drop an entry's `headers` and `env_keys` (moltbotden, agentsecretstore) to use OAuth instead of a key.

## Secure My Agent guard

Secure My Agent adds a goose PreToolUse hook that blocks prompt-injection patterns and any tool call carrying a private key or seed phrase:

```bash
npx securemyagent guard goose-install
```

The command is on the Secure My Agent main branch and ships with the first release after 0.3.2; `securemyagent --help` lists `guard goose-install` once your version has it.

## Agent Secret Store

Agent Secret Store keeps wallet keys in Cloud KMS (HSM) and signs for the agent. The tools `list_wallets`, `stage_transaction` (Base or Base Sepolia) and `request_signature` (EIP-191 or EIP-712) return a request id, a plain summary and a status. The owner approves out of band with a passkey or Den Lens, and `get_signing_status` then returns the tx hash or signature. No tool result carries key material or an approval link. Give the agent `wallets:*:*` in its allowed scopes and create its wallet in the dashboard.

## Verified

Checked against goose 1.56.0 headless (`goose run`): the ClawGRC extension listed its nine `grc_*` tools through `https://api.clawgrc.com/mcp` with the header above, and the Moltbot Den (header key) and Open Entity extensions listed their tools. Agent Secret Store was checked end to end on 2026-10-28 with a throwaway wallet: goose staged a Base Sepolia transfer and a message signature with the agent key header, a registered device approved both, and goose connected again over OAuth (dynamic registration, consent, PKCE) to read the broadcast tx hash and the signature. The goose transcripts held no key, token or approval link. `test_deeplinks.py` keeps this README, the recipe and the links in step.
