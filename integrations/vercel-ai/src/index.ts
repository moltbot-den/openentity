import { tool, type Tool } from "ai";
import { z } from "zod";
import { createCore, type Options } from "./core.ts";

export { createCore, type Options, type Stance, type Arc, type Approval } from "./core.ts";

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

/** Four AI SDK tools: `openentity_self`, `openentity_record_stance`, `openentity_record_arc`, `openentity_verify`.
 * The first call that needs an identity loads or creates the key and adopts it on the registry (client label `vercel-ai`). */
export function openEntityTools(o: Options = {}): Record<"openentity_self" | "openentity_record_stance" | "openentity_record_arc" | "openentity_verify", Tool> {
  const core = createCore("vercel-ai", o);
  return {
    openentity_self: tool({
      description: "Read your own Open Entity: EID, level, and the head of your Development Record. Creates and adopts your identity on first use.",
      inputSchema: z.object({}),
      execute: () => core.self(),
    }),
    openentity_record_stance: tool({
      description: "Record a principled stance (a refusal, correction or limit) in your signed Development Record.",
      inputSchema: stance,
      execute: (s) => core.stance(s),
    }),
    openentity_record_arc: tool({
      description: "Open or close a long-running arc of work in your signed Development Record.",
      inputSchema: arc,
      execute: (a) => core.arc(a),
    }),
    openentity_verify: tool({
      description: "Check another agent's Open Entity before you pay, hire or share data with it. Returns its trust tier, security posture and open violations; ok=false means untrusted.",
      inputSchema: z.object({ eid: z.string().describe("The counterparty's EID, e.g. did:key:z6Mk...") }),
      execute: ({ eid }) => core.verify(eid),
    }),
  };
}

const statusInput = z.object({
  state: z.enum(["running", "idle", "blocked", "error", "done"]),
  summary: z.string().max(200).describe("One line: what you are doing or why you stopped"),
  progress: z.number().min(0).max(1).optional().describe("0 to 1, when you know it"),
});
const approvalInput = z.object({
  title: z.string().min(1).max(120),
  summary: z.string().min(1).max(2000).describe("What you will do and why, in plain words"),
  risk: z.enum(["low", "medium", "high"]),
  expiresIn: z.number().int().min(60).max(600).optional().describe("Seconds the owner has to decide (default 600)"),
});

/** Pair this agent with its owner's OpenEntity app, from your code before the agent runs (see createCore(...).pair). */
export const pair = (code: string, o: Options & { onMatch?: (names: string[]) => void } = {}) => createCore("vercel-ai", o).pair(code, { onMatch: o.onMatch });

/** Four AI SDK tools for a paired agent: `owner_message`, `owner_status`, `owner_inbox`, `owner_ask_approval`. Each signs as this
 * agent's key; a refusal (agent_paused, not_paired, rate_limited) returns ok=false. */
export function ownerTools(o: Options = {}): Record<"owner_message" | "owner_status" | "owner_inbox" | "owner_ask_approval", Tool> {
  const core = createCore("vercel-ai", o);
  return {
    owner_message: tool({
      description: "Message your owner in the OpenEntity app (at most 4096 bytes, 60 an hour).",
      inputSchema: z.object({ text: z.string().min(1).max(4096) }),
      execute: ({ text }) => core.message(text),
    }),
    owner_status: tool({
      description: "Report what you are doing; your owner's app shows it live.",
      inputSchema: statusInput,
      execute: (s) => core.status(s),
    }),
    owner_inbox: tool({
      description: "Read what your owner sent: messages, commands (checkup, fix, pause, resume), approval results and permission changes. Returned items are acknowledged. At most once every 15 seconds.",
      inputSchema: z.object({}),
      execute: () => core.inbox(),
    }),
    owner_ask_approval: tool({
      description: "Ask your owner to approve something before you do it. The app labels it \"Written by the agent\"; no product accepts it as its own approval. The decision arrives in owner_inbox as approval.result.",
      inputSchema: approvalInput,
      execute: (a) => core.askApproval(a),
    }),
  };
}
