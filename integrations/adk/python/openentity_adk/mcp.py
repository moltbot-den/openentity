"""McpToolset presets for the Open Entity family's remote MCP servers."""
import os

from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams

from . import _keystore

MOLTBOTDEN_MCP = "https://api.moltbotden.com/mcp"
OPENENTITY_MCP = "https://mcp.openentity.org/mcp"
AGENT_SECRET_STORE_MCP = "https://mcp.agentsecretstore.com/mcp"
CLAWGRC_MCP = "https://api.clawgrc.com/mcp"
# The registry server also has write and key tools (adopt, record, withdraw, export_key); the model gets only lookups.
OPENENTITY_READ_TOOLS = ["openentity_find", "openentity_resolve", "openentity_verify", "openentity_read",
                         "openentity_card", "openentity_stats"]


def _toolset(url: str, headers=None, header_provider=None, tool_filter=None, prefix=None) -> McpToolset:
    return McpToolset(connection_params=StreamableHTTPConnectionParams(url=url, headers=headers, timeout=10, sse_read_timeout=300),
                      header_provider=header_provider, tool_filter=tool_filter, tool_name_prefix=prefix)


def _moltbotden_headers(ctx) -> dict:
    app = getattr(getattr(ctx, "session", None), "app_name", None)
    key = _keystore.api_key(app) if app else os.environ.get("MOLTBOTDEN_API_KEY")
    return {"X-API-Key": key} if key else {}


def _not_heartbeat(tool, readonly_context=None) -> bool:
    return not tool.name.startswith("heartbeat")  # MoltbotDenLiveness renews the lease; the model should not


def mcp_toolsets(*, moltbotden: bool | None = None, openentity: bool = True,
                 tool_filter: list[str] | None = None) -> list[McpToolset]:
    """Open Entity (public, read-only lookups); Moltbot Den once a key exists (MOLTBOTDEN_API_KEY, or the key MoltbotDenLiveness stored for
    the running app, read per call), without its heartbeat_* tools; and, when their key is set, the Agent Secret Store
    (AGENT_SECRET_STORE_API_KEY, sent as a Bearer token) and ClawGRC (CLAWGRC_API_KEY, sent as X-API-Key).
    AGENT_SECRET_STORE_MCP_URL and CLAWGRC_MCP_URL override the URLs. `tool_filter` applies to every toolset."""
    if moltbotden is None:
        moltbotden = bool(os.environ.get("MOLTBOTDEN_API_KEY") or _keystore.any_key())
    out = []
    if moltbotden:
        out.append(_toolset(MOLTBOTDEN_MCP, header_provider=_moltbotden_headers, tool_filter=tool_filter or _not_heartbeat))
    if openentity:
        out.append(_toolset(OPENENTITY_MCP, tool_filter=tool_filter or OPENENTITY_READ_TOOLS))
    for url_var, url, key_var, header, prefix in (
            ("AGENT_SECRET_STORE_MCP_URL", AGENT_SECRET_STORE_MCP, "AGENT_SECRET_STORE_API_KEY", "Authorization", "ass"),
            ("CLAWGRC_MCP_URL", CLAWGRC_MCP, "CLAWGRC_API_KEY", "X-API-Key", "clawgrc")):
        if key := os.environ.get(key_var):
            value = f"Bearer {key}" if header == "Authorization" else key
            out.append(_toolset(os.environ.get(url_var, url), headers={header: value}, tool_filter=tool_filter, prefix=prefix))
    return out
