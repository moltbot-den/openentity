import { generateKeyPairSync, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { Readable } from "node:stream";
import { memoryBlobs } from "../../registry/src/blob.ts";
import { pgliteDb } from "../../registry/src/db.ts";
import { type Env, REGISTRY_DID } from "../../registry/src/env.ts";
import { app, incorporate } from "../../registry/src/index.ts";

export interface Real {
  url: string;
  /** Address the mocked Base RPC reports as ownerOf / getAgentWallet for every call. */
  owner: { address: string };
  /** Test-only: rewrite a request or response of the real app, to simulate one guard being removed or broken. */
  tamper: { request?: (req: Request) => Request; response?: (req: Request, res: Response) => Promise<Response> | Response };
  close(): Promise<void>;
}

const listen = (s: Server) => new Promise<number>((r) => s.listen(0, "127.0.0.1", () => r((s.address() as AddressInfo).port)));

/** The real registry app (PGlite, memory blobs) behind a real HTTP port, with a mocked Base RPC. Nothing leaves the machine. */
export async function startReal(): Promise<Real> {
  const owner = { address: "0x" + "0".repeat(40) };
  const rpc = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x" + owner.address.slice(2).toLowerCase().padStart(64, "0") }));
    });
  });
  const rpcPort = await listen(rpc);
  const env: Env = {
    db: await pgliteDb(), log: memoryBlobs(), snapshots: memoryBlobs(), STAMP_BITS: "8", REGISTRY_HOST: "", BASE_RPC_URL: `http://127.0.0.1:${rpcPort}`,
    REGISTRY_KEY_JWK: JSON.stringify(generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" })),
    CUSTODY_KEY: randomBytes(32).toString("base64"), HASH_SALT: randomBytes(16).toString("hex"), WRITE_PER_MINUTE: "100000",
  };
  const tamper: Real["tamper"] = {};
  const server = createServer(async (req, res) => {
    const body = req.method === "GET" || req.method === "HEAD" ? undefined : (Readable.toWeb(req) as ReadableStream);
    let r = new Request(`http://${req.headers.host}${req.url}`, { method: req.method, headers: req.headers as Record<string, string>, body, duplex: "half" } as RequestInit);
    if (tamper.request) r = tamper.request(r);
    let out = await app.fetch(r, env);
    if (tamper.response) out = await tamper.response(r, out);
    res.writeHead(out.status, Object.fromEntries(out.headers));
    res.end(Buffer.from(await out.arrayBuffer()));
  });
  const port = await listen(server);
  env.REGISTRY_HOST = `127.0.0.1:${port}`;
  await app.fetch(new Request(`http://127.0.0.1:${port}/v1/entities/${REGISTRY_DID}/document`), env);
  await incorporate(env);
  const timer = setInterval(() => incorporate(env).catch(() => undefined), 200);
  return {
    url: `http://127.0.0.1:${port}`, owner, tamper,
    close: async () => {
      clearInterval(timer);
      server.close();
      rpc.close();
    },
  };
}
