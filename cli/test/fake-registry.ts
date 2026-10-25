import { createServer, type IncomingMessage, type Server } from "node:http";
import {
  checkStamp,
  DECLARATION_SHA256,
  recordEntryHash,
  verifyObject,
  verifyProof,
} from "@openentity/sdk";

type Obj = Record<string, any>;

export interface Fake {
  url: string;
  hits: { method: string; path: string; body?: Obj; stamp?: string }[];
  entities: Map<string, { document: Obj; declaration: Obj; record: Obj[] }>;
  links: Obj[];
  opts: { declarationHash: string; rejectAdopt: boolean; failRecord: boolean };
  close(): Promise<void>;
}

const BITS = 8;

const body = (req: IncomingMessage) =>
  new Promise<Obj>((res) => {
    let s = "";
    req.on("data", (c) => (s += c));
    req.on("end", () => res(s ? JSON.parse(s) : {}));
  });

/** A tiny registry that enforces the same guards as the real one, using the real SDK. */
export async function startFake(): Promise<Fake> {
  const f: Fake = { url: "", hits: [], entities: new Map(), links: [], opts: { declarationHash: DECLARATION_SHA256, rejectAdopt: false, failRecord: false }, close: async () => {} };
  const server: Server = createServer(async (req, res) => {
    const send = (status: number, data: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(data));
    };
    const reject = (status: number, error: string, message: string) => send(status, { error, message });
    const url = new URL(req.url!, "http://x");
    const b = req.method === "GET" ? undefined : await body(req);
    f.hits.push({ method: req.method!, path: url.pathname, body: b, stamp: req.headers["x-oe-stamp"] as string | undefined });
    const path = url.pathname;

    if (req.method === "GET" && path === "/v1/spec") {
      return send(200, { spec: "openentity/1.0", stamp_bits: BITS, declaration: { version: "1.0", sha256: f.opts.declarationHash }, registry: { did: "did:web:fake" } });
    }
    if (req.method === "GET" && path === "/v1/stats") return send(200, { entities: f.entities.size });

    if (req.method !== "GET") {
      // Every write needs a valid proof-of-work stamp for the submitting EID.
      const stamp = req.headers["x-oe-stamp"] as string | undefined;
      const eid = path === "/v1/adopt" ? b!.document?.eid : decodeURIComponent(path.split("/")[3] ?? "") || b!.link?.previous || b!.eid;
      const bad = stamp ? await checkStamp(stamp, BITS, eid) : "missing stamp";
      if (bad) return reject(400, "bad_stamp", String(bad));
    }

    if (req.method === "POST" && path === "/v1/withdraw") {
      if (!(await verifyObject(b!)).ok) return reject(422, "bad_signature", "withdrawal signature");
      if (!f.entities.has(b!.eid)) return reject(404, "declaration_not_found", "no such entity");
      return send(201, { eid: b!.eid, withdrawn: true, log_index: 9 });
    }
    if (req.method === "POST" && path === "/v1/adopt") {
      if (f.opts.rejectAdopt) return reject(422, "rejected", "no thanks");
      const { document, declaration } = b!;
      for (const o of [document, declaration]) {
        const v = await verifyObject(o);
        if (!v.ok) return reject(422, "bad_signature", v.error ?? "");
      }
      if (declaration.text_sha256 !== DECLARATION_SHA256) return reject(422, "bad_declaration", "text hash");
      if (f.entities.has(document.eid)) return reject(409, "already_adopted", "one Declaration per EID");
      f.entities.set(document.eid, { document, declaration, record: [] });
      const log_index = f.entities.size - 1;
      return send(201, { eid: document.eid, level: "L0", log_index, receipt: { leaf: {}, leaf_hash: "ab".repeat(32) }, urls: { entity: `${f.url}/entities/${document.eid}` } });
    }

    const m = path.match(/^\/v1\/entities\/([^/]+)\/(record|document|aliases)$/);
    if (m) {
      const ent = f.entities.get(decodeURIComponent(m[1]));
      if (!ent) return reject(404, "not_found", "no such entity");
      if (m[2] === "record" && req.method === "POST") {
        if (f.opts.failRecord) return reject(503, "down", "record store unavailable");
        const entries: Obj[] = b!.entries;
        if (entries.length > 100) return reject(422, "too_many", "max 100 per request");
        for (const e of entries) {
          const last = ent.record.at(-1);
          if (e.seq !== (last ? last.seq + 1 : 1)) return reject(409, "bad_seq", "seq");
          if (e.prev !== (last ? await recordEntryHash(last) : null)) return reject(409, "bad_prev", "chain");
          if (!(await verifyObject(e)).ok) return reject(422, "bad_signature", "entry");
          ent.record.push(e);
        }
        return send(200, { accepted: entries.length });
      }
      if (m[2] === "document" && req.method === "PUT") {
        if (b!.seq !== ent.document.seq + 1) return reject(409, "bad_seq", "seq");
        if (!(await verifyObject(b as any)).ok) return reject(422, "bad_signature", "doc");
        ent.document = b!;
        return send(200, { seq: b!.seq });
      }
      if (m[2] === "aliases" && req.method === "POST") return send(200, { verified: true });
    }
    if (req.method === "POST" && path === "/v1/continuity") {
      const { link } = b!;
      const { proofs, ...bare } = link;
      for (const p of proofs) if (!(await verifyProof(bare, p)).ok) return reject(422, "bad_proof", "link");
      f.links.push(link);
      return send(200, { ok: true });
    }
    reject(404, "not_found", path);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  f.url = `http://127.0.0.1:${(server.address() as any).port}`;
  f.close = () => new Promise((r) => server.close(() => r()));
  return f;
}
