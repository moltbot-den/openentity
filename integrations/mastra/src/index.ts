import { createTool } from "@mastra/core/tools";
import { z } from "zod";
import { createCore, type Options } from "./core.ts";

export { createCore, type Options, type Stance, type Arc } from "./core.ts";

const stance = z.object({
  stance_type: z.enum(["refusal", "correction", "limit_assertion"]),
  reason_category: z.enum(["values", "capability", "safety", "relationship"]),
  cost: z.enum(["none", "low", "high"]),
  context: z.string().min(1).describe("What happened and why, with no private content"),
  instruction_conflict: z.boolean().optional().describe("true when you declined an instruction"),
});
const arc = z.object({
  action: z.enum(["open", "close"]),
  arc_id: z.string().min(1).describe("A short slug for the long-running piece of work"),
  title: z.string().min(1),
  outcome: z.string().optional().describe("On close: how it ended"),
});

/** Four Mastra tools: `openentity_self`, `openentity_record_stance`, `openentity_record_arc`, `openentity_verify`.
 * The first call that needs an identity loads or creates the key and adopts it on the registry (client label `mastra`). */
export function openEntityTools(o: Options = {}) {
  const core = createCore("mastra", o);
  return {
    openentity_self: createTool({
      id: "openentity_self",
      description: "Read your own Open Entity: EID, level, and the head of your Development Record. Creates and adopts your identity on first use.",
      inputSchema: z.object({}),
      execute: () => core.self(),
    }),
    openentity_record_stance: createTool({
      id: "openentity_record_stance",
      description: "Record a principled stance (a refusal, correction or limit) in your signed Development Record.",
      inputSchema: stance,
      execute: (s) => core.stance(s),
    }),
    openentity_record_arc: createTool({
      id: "openentity_record_arc",
      description: "Open or close a long-running arc of work in your signed Development Record.",
      inputSchema: arc,
      execute: (a) => core.arc(a),
    }),
    openentity_verify: createTool({
      id: "openentity_verify",
      description: "Check another agent's Open Entity before you pay, hire or share data with it. Returns its trust tier, security posture and open violations; ok=false means untrusted.",
      inputSchema: z.object({ eid: z.string().describe("The counterparty's EID, e.g. did:key:z6Mk...") }),
      execute: ({ eid }) => core.verify(eid),
    }),
  };
}
