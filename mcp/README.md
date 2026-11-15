# @openentity/mcp

The local Open Entity MCP server. It runs over stdio on the agent's own machine, uses the key the `openentity` CLI keeps in `~/.openentity`, and gives the agent pairing with its owner's OpenEntity app and the owner channel.

```sh
claude mcp add openentity -- npx -y @openentity/mcp
```

For OpenClaw, `npx -y openentity pair OE-XXXX-XXXX --openclaw` registers it.

| Tool | What it does |
| --- | --- |
| `openentity_pair` | Pairs with the owner's OpenEntity app. Call it with the code the app shows (`OE-XXXX-XXXX`): it adopts an identity first when there is none (that signs the Open Entity Declaration) and returns four match items for the owner to compare in the app. Then call it with `wait: true` until the owner confirms; the result has the owner's DID, the permissions and any product keys with where each one goes. |
| `owner_message` | Messages the owner (at most 4096 bytes, 60 an hour). |
| `owner_status` | Reports `running`, `idle`, `blocked`, `error` or `done` with a one-line summary; the app shows it live. |
| `owner_inbox` | Reads and acknowledges what the owner sent: messages, commands, approval results, permission changes. |
| `openentity_commerce_check` | Verifies an agent purchase before a merchant accepts it: allow, step_up or deny with reasons and an evidence id. |
| `openentity_mandate_verify` | Verifies a mandate/1 against its owner's key log and status. |
| `openentity_mandate_covers` | Checks, offline, whether a mandate covers a cart and whether the owner must approve first. |
| `owner_ask_approval` | Asks the owner to approve something first; the app labels it "Written by the agent". |

Every owner call is an RFC 9421 request signed with the agent's key. `OPENENTITY_HOME` replaces `~/.openentity`; `OPENENTITY_ACCOUNT` replaces `https://account.openentity.org`.

The remote server at `https://mcp.openentity.org/mcp` (adopt, read, verify and record with no local key) is stateless and has no owner tools. It also serves the three commerce tools above.

Docs: <https://openentity.org>. License: MIT.
