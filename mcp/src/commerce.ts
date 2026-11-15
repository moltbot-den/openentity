// Commerce tools shared by the remote server (in-process registry) and the local stdio server (the public registry over HTTPS).
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { mandateCovers } from "@openentity/sdk";
import { z } from "zod";

export type Call = (method: "GET" | "POST", path: string, body?: unknown) => Promise<{ ok: boolean; status: number; body: any }>;
const obj = z.record(z.string(), z.unknown());
const text = (o: unknown, isError = false) => ({ content: [{ type: "text" as const, text: JSON.stringify(o, null, 2) }], ...(isError ? { isError } : {}) });
const out = (r: Awaited<ReturnType<Call>>) => (r.ok ? text(r.body) : text({ status: r.status, error: r.body?.error, message: r.body?.message ?? r.body }, true));

export function registerCommerceTools(server: McpServer, call: Call) {
  server.registerTool(
    "openentity_commerce_check",
    {
      description:
        "Verify an agent purchase before you accept it (Agent Commerce Check): returns allow, step_up or deny with reasons and an evidence_id kept 400 days. Send the agent's signed HTTP request (method, url, headers; add body or body_b64 when the request was signed over it), the cart/1, the merchant policy, and the mandate (or an OE-Mandate header). Free, no key.",
      inputSchema: {
        request: z.object({ method: z.string(), url: z.string(), headers: z.record(z.string(), z.string()), body: z.string().optional(), body_b64: z.string().optional() }),
        cart: obj.describe("cart/1: profile, merchant, agent_did, lines, total, currency, rail, mandate_id"),
        policy: obj.optional().describe("agent_policy: min_level, require_owner, require_mandate, min_security_band, accept_issuers, min_owner_level; or {merchant: <did>} to use the policy that merchant published"),
        mandate: obj.optional().describe("mandate/1, when not in an OE-Mandate header"),
        approval: obj.optional().describe("{approval: approval/2.0, verifier_did, request_id}: the owner's approval of this exact cart, after a step_up"),
      },
    },
    async (a) => out(await call("POST", "/commerce/check", a)),
  );
  server.registerTool(
    "openentity_mandate_verify",
    {
      description: "Verify a mandate/1 against its owner's key log and status URL: who issued it, for which agent, the limits and scope, and whether it is still active. Pass agent_did to also check the agent presenting it.",
      inputSchema: { mandate: obj, agent_did: z.string().max(200).optional() },
    },
    async (a) => out(await call("POST", "/commerce/mandate", a)),
  );
  server.registerTool(
    "openentity_mandate_covers",
    {
      description: "Verify whether a mandate/1 covers a cart/1 (scope, currency, rail, per-purchase and period limits) and whether the purchase needs the owner's approval first. Offline: it does not check the mandate's signature; use openentity_mandate_verify for that.",
      inputSchema: { mandate: obj, cart: obj, period_spent: z.number().int().min(0).optional(), total_spent: z.number().int().min(0).optional() },
    },
    async ({ mandate, cart, period_spent, total_spent }) => {
      try {
        return text(mandateCovers(mandate as never, cart, { spent: { period_spent, total_spent } }));
      } catch (e) {
        return text({ error: "bad_request", message: String((e as Error).message) }, true);
      }
    },
  );
}
