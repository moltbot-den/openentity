// The local Open Entity MCP server (stdio, src/stdio.ts): pairing and the owner channel for the agent whose key the openentity
// CLI keeps in ~/.openentity (OPENENTITY_HOME). Claude Code: `claude mcp add openentity -- npx -y @openentity/mcp`;
// `openentity pair --openclaw` registers it for OpenClaw. The remote server (src/index.ts) is stateless and holds no key.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Owner } from "@openentity/sdk";
import { z } from "zod";
import { ACCOUNT, pairCmd } from "../../cli/src/pair.ts";
import { loadEntity } from "../../cli/src/store.ts";
import pkg from "../package.json";

const text = (o: unknown, isError = false) => ({
  content: [{ type: "text" as const, text: typeof o === "string" ? o : JSON.stringify(o, null, 2) }],
  ...(isError ? { isError } : {}),
});
const failed = (e: any) => text(e?.code && typeof e.code === "string" ? `${e.code}: ${e.message}` : String(e?.message ?? e), true);

export function localServer(o: { account?: string } = {}): McpServer {
  const account = o.account ?? process.env.OPENENTITY_ACCOUNT ?? ACCOUNT;
  const server = new McpServer({ name: "openentity", version: pkg.version });
  /** One owner-channel call signed with the current entity's key. */
  async function withOwner<T>(fn: (o: Owner) => Promise<T>, done: (r: T) => unknown) {
    let o: Owner;
    try {
      o = new Owner((await loadEntity({})).kp, { account });
    } catch {
      return text("This agent has no Open Entity key here yet: call openentity_pair with the code from your owner's OpenEntity app.", true);
    }
    return fn(o).then((r) => text(done(r)), failed);
  }

  // One pairing at a time. The first call returns the match items (the owner compares them); the second waits for the owner.
  let pending: { code: string; result: Promise<unknown>; settled: boolean } | undefined;
  server.registerTool(
    "openentity_pair",
    {
      description:
        "Pair this agent with its owner's OpenEntity app. Call with the code the app shows (OE-XXXX-XXXX): it adopts an identity first if there is none (that signs the Open Entity Declaration) and returns four match items. Show them to your owner, who confirms in the app; then call again with wait=true until it reports the result.",
      inputSchema: {
        code: z.string().max(20).optional().describe("The pairing code from the owner's app, OE-XXXX-XXXX"),
        wait: z.boolean().optional().describe("true: wait (up to 50 seconds per call) for the owner to confirm the pairing started before"),
      },
    },
    async ({ code, wait }) => {
      if (code && (!pending || pending.settled)) {
        const lines: string[] = [];
        let shown!: () => void;
        const matchShown = new Promise<void>((ok) => (shown = ok));
        const framework = (server.server.getClientVersion()?.name ?? "mcp").slice(0, 64);
        const p = { code, settled: false, result: undefined as unknown as Promise<unknown> };
        p.result = pairCmd({
          args: [code],
          v: { account, framework, sdk: "@openentity/mcp", sdk_version: pkg.version },
          say: (line) => {
            lines.push(line);
            if (line.startsWith("Match:")) shown();
          },
        }).finally(() => (p.settled = true));
        p.result.catch(() => {}); // read by the wait call; never an unhandled rejection
        pending = p;
        const first = await Promise.race([matchShown.then(() => "match"), p.result.then(() => "done", () => "failed")]);
        if (first === "failed") return p.result.then(() => text("unreachable"), failed);
        return text(`${lines.join("\n")}\n\nTell your owner these four items. Once they confirm in the OpenEntity app, call openentity_pair with wait=true.`);
      }
      if (!pending) return text("Start with openentity_pair code=OE-XXXX-XXXX (the code your owner's OpenEntity app shows).", true);
      if (code && !wait) return text(`A pairing for ${pending.code} is still waiting for the owner; call openentity_pair with wait=true.`, true);
      const timeout = new Promise<"waiting">((ok) => setTimeout(() => ok("waiting"), 50_000).unref?.());
      const r = await Promise.race([pending.result.then((x) => ({ x }), (e) => ({ e })), timeout]);
      if (r === "waiting") return text("Still waiting for the owner to confirm in the OpenEntity app. Call openentity_pair with wait=true again.");
      if ("e" in r) return failed(r.e);
      const { json } = r.x as { json: { credentials: unknown[] } };
      return text({
        ...json,
        ...(json.credentials.length ? { warning: "SECRET: these product keys are shown once. Put each where put_it_in says; never paste them into chat or share them." } : {}),
        next: "Use owner_message, owner_status, owner_inbox and owner_ask_approval.",
      });
    },
  );

  server.registerTool(
    "owner_message",
    { description: "Message your owner in the OpenEntity app (at most 4096 bytes; 60 an hour).", inputSchema: { text: z.string().min(1).max(4096) } },
    ({ text: t }) => withOwner((o) => o.message(t), (r) => `sent (${r.id})`),
  );

  server.registerTool(
    "owner_status",
    {
      description: "Report what you are doing; your owner's app shows it live.",
      inputSchema: {
        state: z.enum(["running", "idle", "blocked", "error", "done"]),
        summary: z.string().max(200).describe("One line: what you are doing or why you stopped"),
        progress: z.number().min(0).max(1).optional().describe("0 to 1, when you know it"),
      },
    },
    (s) => withOwner((o) => o.status(s), () => `status: ${s.state}`),
  );

  server.registerTool(
    "owner_inbox",
    {
      description: "Read what your owner sent: messages, commands (checkup, fix, pause, resume), approval results and permission changes. Returned items are acknowledged. At most once every 15 seconds.",
      inputSchema: {},
    },
    () => withOwner((o) => o.inbox(), (r) => (r.items.length ? r : "nothing new")),
  );

  server.registerTool(
    "owner_ask_approval",
    {
      description:
        "Ask your owner to approve something before you do it. The app labels it \"Written by the agent\"; no product accepts it as its own approval. The decision arrives in owner_inbox as approval.result, or pass wait=true to wait for it.",
      inputSchema: {
        title: z.string().min(1).max(120),
        summary: z.string().min(1).max(2000).describe("What you will do and why, in plain words"),
        risk: z.enum(["low", "medium", "high"]),
        expires_in: z.number().int().min(60).max(600).default(600).describe("Seconds the owner has to decide"),
        wait: z.boolean().default(false),
      },
    },
    (a) => withOwner((o) => o.askApproval({ title: a.title, summary: a.summary, risk: a.risk, expiresIn: a.expires_in }, { wait: a.wait }), (r) => r),
  );

  return server;
}
