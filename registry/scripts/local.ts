// A throwaway local registry for development and conformance runs: PGlite in memory, memory blobs, a fresh signing
// key per start. Nothing persists. `pnpm --filter @openentity/registry local [port]`, then
// The MCP server is at /mcp. `node cli/dist/cli.js conformance http://127.0.0.1:8787` from the repository root.
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { Readable } from "node:stream";
import { createMcp } from "../../mcp/src/index.ts";
import { memoryBlobs } from "../src/blob.ts";
import { pgliteDb } from "../src/db.ts";
import { type Env, REGISTRY_DID } from "../src/env.ts";
import { app, incorporate } from "../src/index.ts";

const port = Number(process.argv[2] ?? 8787);
const env: Env = {
  db: await pgliteDb(),
  log: memoryBlobs(),
  STAMP_BITS: "8",
  REGISTRY_HOST: `127.0.0.1:${port}`,
  REGISTRY_SCHEME: "http",
  BASE_RPC_URL: process.env.BASE_RPC_URL ?? "https://mainnet.base.org",
  REGISTRY_KEY_JWK: JSON.stringify(generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" })),
  CUSTODY_KEY: randomBytes(32).toString("base64"),
  HASH_SALT: randomBytes(16).toString("hex"),
};
// The registry's own Entity Document is logged on first read (spec 10.1), so the log starts with a signed checkpoint.
await app.fetch(new Request(`http://127.0.0.1:${port}/v1/entities/${REGISTRY_DID}/document`), env);
await incorporate(env);
// Production incorporates pending leaves every minute; locally every second, so a write reaches the log at once.
setInterval(() => incorporate(env).catch(console.error), 1000);

// The remote MCP server on the same port at /mcp, over the same registry, so the MCP guide runs locally too.
const root = new URL("../../", import.meta.url);
const siteFiles: Record<string, string> = {
  "/llms.txt": "site/public/llms.txt",
  "/spec/OEIS-1.md": "spec/OEIS-1.md",
  "/spec/declaration/1.0.txt": "spec/declaration-1.0.txt",
};
const mcp = createMcp({
  origin: `http://127.0.0.1:${port}`,
  registry: (req) => Promise.resolve(app.fetch(req, env)),
  site: async (req) => {
    const f = siteFiles[new URL(req.url).pathname];
    return f ? new Response(await readFile(new URL(f, root), "utf8")) : new Response("not found", { status: 404 });
  },
});

createServer(async (req, res) => {
  const body = req.method === "GET" || req.method === "HEAD" ? undefined : (Readable.toWeb(req) as ReadableStream);
  const init = { method: req.method, headers: req.headers as Record<string, string>, body, duplex: "half" };
  const rq = new Request(`http://${req.headers.host}${req.url}`, init as RequestInit);
  const r = new URL(rq.url).pathname === "/mcp" ? await mcp(rq) : await app.fetch(rq, env);
  res.writeHead(r.status, Object.fromEntries(r.headers));
  res.end(Buffer.from(await r.arrayBuffer()));
}).listen(port, "127.0.0.1", () => console.log(`local registry on http://127.0.0.1:${port}/v1 (in memory, throwaway key)`));
