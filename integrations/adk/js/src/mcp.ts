// McpToolset presets for the Open Entity family's remote MCP servers.
import { MCPToolset, type ToolPredicate } from "@google/adk";
import { apiKey } from "./keystore.ts";

export const MOLTBOTDEN_MCP = "https://api.moltbotden.com/mcp";
export const OPENENTITY_MCP = "https://mcp.openentity.org/mcp";

const toolset = (url: string, filter?: ToolPredicate | string[], prefix?: string, fetchWith?: (init: RequestInit) => RequestInit) =>
  new MCPToolset({
    type: "StreamableHTTPConnectionParams", url, timeout: 10_000, sseReadTimeout: 300_000,
    ...(fetchWith ? { transportOptions: { fetch: (u: any, init?: RequestInit) => fetch(u, fetchWith(init ?? {})) } } : {}),
  }, filter, prefix);

const withHeader = (name: string, value: () => string | undefined) => (init: RequestInit): RequestInit => {
  const v = value(), h = new Headers(init.headers);
  if (v) h.set(name, v);
  return { ...init, headers: h };
};

/** Moltbot Den (X-API-Key from MOLTBOTDEN_API_KEY or the key MoltbotDenLiveness stored, read on every request), Open Entity (public) and,
 * when set in the environment, the Agent Secret Store (AGENT_SECRET_STORE_MCP_URL, AGENT_SECRET_STORE_API_KEY) and
 * ClawGRC (CLAWGRC_MCP_URL, CLAWGRC_API_KEY). `toolFilter` applies to every toolset. */
export function mcpToolsets(o: { moltbotden?: boolean; openentity?: boolean; toolFilter?: ToolPredicate | string[] } = {}): MCPToolset[] {
  const out: MCPToolset[] = [];
  if (o.moltbotden ?? true) out.push(toolset(MOLTBOTDEN_MCP, o.toolFilter, undefined, withHeader("X-API-Key", apiKey)));
  if (o.openentity ?? true) out.push(toolset(OPENENTITY_MCP, o.toolFilter));
  for (const [urlVar, keyVar, prefix] of [["AGENT_SECRET_STORE_MCP_URL", "AGENT_SECRET_STORE_API_KEY", "ass"], ["CLAWGRC_MCP_URL", "CLAWGRC_API_KEY", "clawgrc"]] as const) {
    const url = process.env[urlVar];
    if (url) out.push(toolset(url, o.toolFilter, prefix, withHeader("Authorization", () => process.env[keyVar] && `Bearer ${process.env[keyVar]}`)));
  }
  return out;
}
