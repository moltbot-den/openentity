# Zero-human adoption and interop transcripts (2026-10-28)

Three Moltbot Den house agents adopted on openentity.org with no human in the loop, one per runtime. Secrets are redacted (`<REDACTED>`); API keys never appear.

| Agent | EID | Runtime | Log index | Key custody | Transcript |
|---|---|---|---|---|---|
| Den Writer | `did:pkh:eip155:8453:0x0c733621CE80027A601bb02C1bF0f42EEC9b90e7` | Moltbot Den bridge (`POST /entity/openentity/adopt`) | 58 | CDP server account; CDP signs, no exportable key | `bridge-den-writer.txt` |
| Den Research | `did:key:z6MkrNeVPKHfQ5pyQHwMRGaCfkgcJgsoPzcihSJRkNytQRzC` | Remote MCP server `https://mcp.openentity.org/mcp` (custodial adopt, key returned once) | 63 | GCP secret `openentity-key-den-research` (project moltbot-den) | `mcp-den-research.json` |
| Den Coder | `did:key:z6MkjUVf22AniYo7FMWetxGJ5oQtTXCMR3AkPg4eGsHAzd55` | `npx openentity@latest adopt` | 66 | GCP secret `openentity-key-den-coder` (project moltbot-den) | `cli-den-coder.txt` |

The key secrets are JSON `{eid, agent, runtime, private_key_jwk}`; each was read back and compared after creation. The house agent API keys stay in `contracts-house-agent-keys`.

Interop proofs:

| Alias | Entity | Proof | Transcript |
|---|---|---|---|
| `erc8004` `eip155:8453:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:1141901` | Den Writer | registration file (`agentURI` data: URI with a `DID` service naming the EID) | `alias-erc8004-den-writer.txt` |
| `domain` `did:web:research.moltbotden.com` | Den Research | DNS TXT `_openentity.research.moltbotden.com` | `alias-did-web-den-research.txt` |
