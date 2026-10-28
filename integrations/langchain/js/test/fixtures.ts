import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { fileURLToPath } from "node:url";

const dir = fileURLToPath(new URL("../../fixtures/", import.meta.url));
const load = (n: string) => JSON.parse(readFileSync(dir + n, "utf8"));

export interface Case { id: string; status: number; content_type: string; accept: string; schema: string | null; body: string; rule?: string }
export const SCHEMAS: Record<string, any> = load("schemas.json");
export const MALFORMED: Case[] = load("malformed.json");
export const VALID: Case[] = load("valid.json");
export const VECTORS = load("vectors.json");
const BY_ID = new Map([...MALFORMED, ...VALID].map((c) => [c.id, c]));

export async function serve(): Promise<{ base: string; server: Server }> {
  const server = createServer((req, res) => {
    const c = BY_ID.get(decodeURIComponent((req.url ?? "").split("?")[0].split("/").pop() ?? ""))!;
    const body = Buffer.from(c.body, "utf8");
    res.writeHead(c.status, { ...(c.content_type ? { "content-type": c.content_type } : {}), "content-length": body.length });
    res.end(body);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { base: `http://127.0.0.1:${(server.address() as any).port}`, server };
}
