// `npx -y @openentity/mcp`: the local server (src/local.ts) on stdio. Nothing else may write to stdout.
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { localServer } from "./local.ts";

await localServer().connect(new StdioServerTransport());
