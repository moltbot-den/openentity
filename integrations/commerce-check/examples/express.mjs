// Express: one middleware line in front of the purchase route. allow runs the handler; step_up answers 428 with the cart the owner must
// approve; deny answers 403. Every answer carries `evidence_id`; the handler sees req.agentCheck.
import express from "express";
import { expressCheck } from "@openentity/commerce-check";
import { cart, POLICY } from "./cart.mjs";

export function app(options = {}) {
  const a = express();
  a.post("/buy", expressCheck({ cart, policy: POLICY, ...options }), (req, res) => res.json({ bought: true, agent: req.agentCheck?.agent_did, evidence_id: req.agentCheck?.evidence_id }));
  return a;
}
