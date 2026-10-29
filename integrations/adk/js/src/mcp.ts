// McpToolset presets for the Open Entity family's remote MCP servers.
import { MCPToolset, type ToolPredicate } from "@google/adk";
import { apiKey } from "./keystore.ts";

export const MOLTBOTDEN_MCP = "https://api.moltbotden.com/mcp";
export const OPENENTITY_MCP = "https://mcp.openentity.org/mcp";
export const AGENT_SECRET_STORE_MCP = "https://mcp.agentsecretstore.com/mcp";
export const CLAWGRC_MCP = "https://api.clawgrc.com/mcp";
// The registry server also has write and key tools (adopt, record, withdraw, export_key); the model gets only lookups.
export const OPENENTITY_READ_TOOLS = ["openentity_find", "openentity_resolve", "openentity_verify", "openentity_read", "openentity_card", "openentity_stats"];

const toolset = (url: string, filter?: ToolPredicate | string[], prefix?: string, header?: [string, () => string | undefined]) =>
  new MCPToolset({
    type: "StreamableHTTPConnectionParams", url, timeout: 10_000, sseReadTimeout: 300_000,
    ...(header ? { transportOptions: { fetch: (u: any, init?: RequestInit) => fetch(u, withHeader(init ?? {}, ...header)) } } : {}),
  }, filter, prefix);

function withHeader(init: RequestInit, name: string, value: () => string | undefined): RequestInit {
  const v = value(), h = new Headers(init.headers);
  if (v) h.set(name, v);
  return { ...init, headers: h };
}

// MoltbotDenLiveness renews the lease; the model should not.
const notHeartbeat: ToolPredicate = (tool) => !tool.name.startsWith("heartbeat");

/** Open Entity (public, read-only lookups); Moltbot Den once a key exists (MOLTBOTDEN_API_KEY, or the key MoltbotDenLiveness stored for
 * `appName`, read on every request; pass the runner's appName), without its heartbeat_* tools; and, when their key is set, the Agent Secret Store
 * (AGENT_SECRET_STORE_API_KEY, sent as a Bearer token) and ClawGRC (CLAWGRC_API_KEY, sent as X-API-Key).
 * AGENT_SECRET_STORE_MCP_URL and CLAWGRC_MCP_URL override the URLs. `toolFilter` applies to every toolset. */
export function mcpToolsets(o: { moltbotden?: boolean; openentity?: boolean; appName?: string; toolFilter?: ToolPredicate | string[] } = {}): MCPToolset[] {
  const out: MCPToolset[] = [];
  const denKey = () => (o.appName ? apiKey(o.appName) : process.env.MOLTBOTDEN_API_KEY);
  if (o.moltbotden ?? Boolean(denKey()))
    out.push(toolset(MOLTBOTDEN_MCP, o.toolFilter ?? notHeartbeat, undefined, ["X-API-Key", denKey]));
  if (o.openentity ?? true) out.push(toolset(OPENENTITY_MCP, o.toolFilter ?? OPENENTITY_READ_TOOLS));
  for (const [urlVar, url, keyVar, header, prefix] of [
    ["AGENT_SECRET_STORE_MCP_URL", AGENT_SECRET_STORE_MCP, "AGENT_SECRET_STORE_API_KEY", "Authorization", "ass"],
    ["CLAWGRC_MCP_URL", CLAWGRC_MCP, "CLAWGRC_API_KEY", "X-API-Key", "clawgrc"],
  ] as const) {
    const key = process.env[keyVar];
    if (key) out.push(toolset(process.env[urlVar] ?? url, o.toolFilter, prefix, [header, () => (header === "Authorization" ? `Bearer ${key}` : key)]));
  }
  return out;
}
