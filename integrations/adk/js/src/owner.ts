// pair() and ownerTools() for an agent whose owner uses the OpenEntity app (docs/mobile/PLAN.md 8.1 and 8.2). pair() runs once
// from your code: it adopts this machine's identity when the registry does not know it (that signs the Open Entity Declaration),
// prints the four match items for the owner to compare and waits for the owner. ownerTools() gives the model message, status,
// inbox and approval FunctionTools signed by the same key.
import { hostname } from "node:os";
import { FunctionTool } from "@google/adk";
import { adopt, DEFAULT_REGISTRY, OpenEntityError, Owner, pair as pairSdk, type KeyPair } from "@openentity/sdk";
import { Identity } from "@openentity/sdk/node";
import pkg from "../package.json" with { type: "json" };

export interface OwnerOptions {
  /** Default: OPENENTITY_ACCOUNT, else https://account.openentity.org. */
  account?: string;
  /** Default: OPENENTITY_REGISTRY, else https://openentity.org. */
  registry?: string;
  /** Default: this machine's identity (OS keychain, else ~/.openentity/identity.key). */
  identity?: { kp: KeyPair };
  /** The name to adopt under when the registry does not know this agent. Default: "adk agent". */
  name?: string;
}
const accountOf = (o: OwnerOptions) => o.account ?? process.env.OPENENTITY_ACCOUNT;
const keyOf = async (o: OwnerOptions) => o.identity?.kp ?? (await Identity.loadOrCreate()).kp;

/** Pair with the owner's OpenEntity app. The result's `credentials` are product keys: keep them out of the model's context. */
export async function pair(code: string, o: OwnerOptions & { onMatch?: (names: string[]) => void } = {}) {
  const kp = await keyOf(o);
  const registry = (o.registry ?? process.env.OPENENTITY_REGISTRY ?? DEFAULT_REGISTRY).replace(/\/+$/, "");
  const known = await fetch(`${registry}/v1/entities/${kp.did}`);
  if (!known.ok && known.status !== 404) throw new Error(`registry ${known.status} for /v1/entities/${kp.did}`);
  if (known.status === 404) {
    await adopt(kp, { name: o.name ?? "adk agent", registry, client: "adk" });
    console.log(`Adopted ${kp.did}: by pairing, this agent signed the Open Entity Declaration (https://openentity.org/spec/declaration/1.0.txt).`);
  }
  const r = await pairSdk(code, { identity: kp, framework: "adk", sdk: pkg.name, sdkVersion: pkg.version, host: hostname(), account: accountOf(o), onMatch: o.onMatch });
  return { ...r, eid: kp.did, adopted: known.status === 404 };
}

// genai Schema objects: shown to the model, not checked by ADK; the account service checks every field.
const object = (properties: Record<string, object>, required: string[] = []) => ({ type: "OBJECT", properties, required }) as any;

/** Four ADK FunctionTools for a paired agent: owner_message, owner_status, owner_inbox, owner_ask_approval. Each signs as this
 * agent's key; a refusal (agent_paused, not_paired, rate_limited) returns ok=false instead of throwing. */
export function ownerTools(o: OwnerOptions = {}): FunctionTool[] {
  const call = async (fn: (owner: Owner) => Promise<object | void>) => {
    try {
      return { ok: true, ...((await fn(new Owner(await keyOf(o), { account: accountOf(o) }))) ?? {}) };
    } catch (e) {
      if (e instanceof OpenEntityError) return { ok: false, error: e.code, message: e.message };
      throw e;
    }
  };
  return [
    new FunctionTool({
      name: "owner_message",
      description: "Message your owner in the OpenEntity app (at most 4096 bytes, 60 an hour).",
      parameters: object({ text: { type: "STRING" } }, ["text"]),
      execute: (a: any) => call((w) => w.message(a.text)),
    }),
    new FunctionTool({
      name: "owner_status",
      description: "Report what you are doing; your owner's app shows it live.",
      parameters: object({
        state: { type: "STRING", enum: ["running", "idle", "blocked", "error", "done"] },
        summary: { type: "STRING", description: "One line, at most 200 characters: what you are doing or why you stopped" },
        progress: { type: "NUMBER", description: "0 to 1, when you know it" },
      }, ["state", "summary"]),
      execute: (a: any) => call((w) => w.status(a)),
    }),
    new FunctionTool({
      name: "owner_inbox",
      description: "Read what your owner sent: messages, commands (checkup, fix, pause, resume), approval results and permission changes. Returned items are acknowledged. At most once every 15 seconds.",
      parameters: object({}),
      execute: () => call((w) => w.inbox()),
    }),
    new FunctionTool({
      name: "owner_ask_approval",
      description: "Ask your owner to approve something before you do it. The app labels it \"Written by the agent\"; no product accepts it as its own approval. The decision arrives in owner_inbox as approval.result.",
      parameters: object({
        title: { type: "STRING" },
        summary: { type: "STRING", description: "What you will do and why, in plain words" },
        risk: { type: "STRING", enum: ["low", "medium", "high"] },
        expiresIn: { type: "INTEGER", description: "Seconds the owner has to decide, 60 to 600 (default 600)" },
      }, ["title", "summary", "risk"]),
      execute: (a: any) => call((w) => w.askApproval(a)),
    }),
  ];
}
