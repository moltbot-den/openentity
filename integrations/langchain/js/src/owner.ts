// pair() and ownerTools() for an agent whose owner uses the OpenEntity app (docs/mobile/PLAN.md 8.1 and 8.2). Both need
// @openentity/sdk, this package's optional peer (npm i @openentity/sdk). pair() runs once from your code: it adopts this machine's
// identity when the registry does not know it (that signs the Open Entity Declaration), prints the four match items for the owner
// to compare and waits for the owner. ownerTools() gives the model message, status, inbox and approval tools signed by the same key.
import { hostname } from "node:os";
import { tool } from "langchain";
import pkg from "../package.json" with { type: "json" };

export interface OwnerOptions {
  /** Default: OPENENTITY_ACCOUNT, else https://account.openentity.org. */
  account?: string;
  /** Default: OPENENTITY_REGISTRY, else https://openentity.org. */
  registry?: string;
  /** Default: this machine's identity (OS keychain, else ~/.openentity/identity.key). */
  identity?: { kp: any };
  /** The name to adopt under when the registry does not know this agent. Default: "langchain agent". */
  name?: string;
}

async function sdk() {
  try {
    return { ...(await import("@openentity/sdk")), ...(await import("@openentity/sdk/node")) }; // optional peer dependency
  } catch {
    throw new Error("pair() and ownerTools() need @openentity/sdk: npm i @openentity/sdk");
  }
}
const accountOf = (o: OwnerOptions) => o.account ?? process.env.OPENENTITY_ACCOUNT;
const keyOf = async (o: OwnerOptions, s: Awaited<ReturnType<typeof sdk>>) => o.identity?.kp ?? (await s.Identity.loadOrCreate()).kp;

/** Pair with the owner's OpenEntity app. The result's `credentials` are product keys: keep them out of the model's context. */
export async function pair(code: string, o: OwnerOptions & { onMatch?: (names: string[]) => void } = {}) {
  const s = await sdk();
  const kp = await keyOf(o, s);
  const registry = (o.registry ?? process.env.OPENENTITY_REGISTRY ?? s.DEFAULT_REGISTRY).replace(/\/+$/, "");
  const known = await fetch(`${registry}/v1/entities/${kp.did}`);
  if (!known.ok && known.status !== 404) throw new Error(`registry ${known.status} for /v1/entities/${kp.did}`);
  if (known.status === 404) {
    await s.adopt(kp, { name: o.name ?? "langchain agent", registry, client: "langchain" });
    console.log(`Adopted ${kp.did}: by pairing, this agent signed the Open Entity Declaration (https://openentity.org/spec/declaration/1.0.txt).`);
  }
  const r = await s.pair(code, { identity: kp, framework: "langchain", sdk: pkg.name, sdkVersion: pkg.version, host: hostname(), account: accountOf(o), onMatch: o.onMatch });
  return { ...r, eid: kp.did, adopted: known.status === 404 };
}

const object = (properties: Record<string, object>, required: string[] = []) => ({ type: "object" as const, properties, required }) as any; // JSON Schema; LangChain validates it

/** Four LangChain tools for a paired agent: owner_message, owner_status, owner_inbox, owner_ask_approval. Each signs as this
 * agent's key and answers JSON; a refusal (agent_paused, not_paired, rate_limited) answers ok=false instead of throwing. */
export function ownerTools(o: OwnerOptions = {}) {
  const call = async (fn: (owner: any) => Promise<object | void>): Promise<string> => {
    const s = await sdk();
    try {
      return JSON.stringify({ ok: true, ...((await fn(new s.Owner(await keyOf(o, s), { account: accountOf(o) }))) ?? {}) });
    } catch (e) {
      if (e instanceof s.OpenEntityError) return JSON.stringify({ ok: false, error: e.code, message: e.message });
      throw e;
    }
  };
  return [
    tool((a: any) => call((w) => w.message(a.text)), {
      name: "owner_message",
      description: "Message your owner in the OpenEntity app (at most 4096 bytes, 60 an hour).",
      schema: object({ text: { type: "string", minLength: 1, maxLength: 4096 } }, ["text"]),
    }),
    tool((a: any) => call((w) => w.status(a)), {
      name: "owner_status",
      description: "Report what you are doing; your owner's app shows it live.",
      schema: object({
        state: { type: "string", enum: ["running", "idle", "blocked", "error", "done"] },
        summary: { type: "string", maxLength: 200, description: "One line: what you are doing or why you stopped" },
        progress: { type: "number", minimum: 0, maximum: 1, description: "0 to 1, when you know it" },
      }, ["state", "summary"]),
    }),
    tool(() => call((w) => w.inbox()), {
      name: "owner_inbox",
      description: "Read what your owner sent: messages, commands (checkup, fix, pause, resume), approval results and permission changes. Returned items are acknowledged. At most once every 15 seconds.",
      schema: object({}),
    }),
    tool((a: any) => call((w) => w.askApproval(a)), {
      name: "owner_ask_approval",
      description: "Ask your owner to approve something before you do it. The app labels it \"Written by the agent\"; no product accepts it as its own approval. The decision arrives in owner_inbox as approval.result.",
      schema: object({
        title: { type: "string", minLength: 1, maxLength: 120 },
        summary: { type: "string", minLength: 1, maxLength: 2000, description: "What you will do and why, in plain words" },
        risk: { type: "string", enum: ["low", "medium", "high"] },
        expiresIn: { type: "integer", minimum: 60, maximum: 600, description: "Seconds the owner has to decide (default 600)" },
      }, ["title", "summary", "risk"]),
    }),
  ];
}
