"""McpToolset presets for the Open Entity family's remote MCP servers."""
import os

from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams

from . import _keystore

MOLTBOTDEN_MCP = "https://api.moltbotden.com/mcp"
OPENENTITY_MCP = "https://mcp.openentity.org/mcp"


def _toolset(url: str, headers=None, header_provider=None, tool_filter=None, prefix=None) -> McpToolset:
    return McpToolset(connection_params=StreamableHTTPConnectionParams(url=url, headers=headers, timeout=10, sse_read_timeout=300),
                      header_provider=header_provider, tool_filter=tool_filter, tool_name_prefix=prefix)


def mcp_toolsets(*, moltbotden: bool = True, openentity: bool = True, tool_filter: list[str] | None = None) -> list[McpToolset]:
    """Moltbot Den (needs MOLTBOTDEN_API_KEY or the key MoltbotDenLiveness stored; read per call, so a key that arrives
    after start-up works), Open Entity (public), and, when set in the environment, the Agent Secret Store
    (AGENT_SECRET_STORE_MCP_URL, AGENT_SECRET_STORE_API_KEY) and ClawGRC (CLAWGRC_MCP_URL, CLAWGRC_API_KEY).
    `tool_filter` applies to every toolset; build your own McpToolset to filter one."""
    out = []
    if moltbotden:
        out.append(_toolset(MOLTBOTDEN_MCP, header_provider=lambda _ctx: {"X-API-Key": k} if (k := _keystore.api_key()) else {},
                            tool_filter=tool_filter))
    if openentity:
        out.append(_toolset(OPENENTITY_MCP, tool_filter=tool_filter))
    for url_var, key_var, prefix in (("AGENT_SECRET_STORE_MCP_URL", "AGENT_SECRET_STORE_API_KEY", "ass"),
                                     ("CLAWGRC_MCP_URL", "CLAWGRC_API_KEY", "clawgrc")):
        if url := os.environ.get(url_var):
            key = os.environ.get(key_var)
            out.append(_toolset(url, headers={"Authorization": f"Bearer {key}"} if key else None, tool_filter=tool_filter, prefix=prefix))
    return out
