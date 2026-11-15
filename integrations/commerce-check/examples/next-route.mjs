// Next.js App Router: app/buy/route.ts exports the wrapped handler. The handler reads req.agentCheck.
import { nextCheck } from "@openentity/commerce-check";
import { cart, POLICY } from "./cart.mjs";

export function route(options = {}) {
  return nextCheck({ cart, policy: POLICY, ...options }, (req) => Response.json({ bought: true, agent: req.agentCheck?.agent_did, evidence_id: req.agentCheck?.evidence_id }));
}
export const POST = route();
