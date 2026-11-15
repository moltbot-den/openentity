// Hono, also Cloudflare Workers (export default app). The handler reads c.get("agentCheck").
import { Hono } from "hono";
import { honoCheck } from "@openentity/commerce-check";
import { cart, POLICY } from "./cart.mjs";

export function app(options = {}) {
  const a = new Hono();
  a.post("/buy", honoCheck({ cart, policy: POLICY, ...options }), (c) => c.json({ bought: true, agent: c.get("agentCheck")?.agent_did, evidence_id: c.get("agentCheck")?.evidence_id }));
  return a;
}
