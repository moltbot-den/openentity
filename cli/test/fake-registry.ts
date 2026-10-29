import { createServer, type IncomingMessage, type Server } from "node:http";
import {
  canonicalize,
  checkpointBody,
  checkStamp,
  DECLARATION_SHA256,
  generateKeyPair,
  inclusionProof,
  leafHash,
  merkleRoot,
  recordEntryHash,
  signNote,
  verifyObject,
  verifyProof,
} from "@openentity/sdk";

type Obj = Record<string, any>;

export interface Fake {
  url: string;
  hits: { method: string; path: string; search: string; body?: Obj; stamp?: string }[];
  disputes: Obj[];
  entities: Map<string, { document: Obj; declaration: Obj; record: Obj[] }>;
  links: Obj[];
  attestations?: Obj[]; // rows as GET /v1/entities/:eid/attestations returns them
  opts: { declarationHash: string; rejectAdopt: boolean; rejectLink: boolean; failRecord: boolean; broken: Set<"checkpoint" | "tiles" | "inclusion" | "turnstile" | "html-errors" | "stamp-bits"> };
  close(): Promise<void>;
}

const BITS = 8;
const LOG_ORIGIN = "fake.test/log";
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const LEAVES = 5;

const body = (req: IncomingMessage) =>
  new Promise<Obj>((res) => {
    let s = "";
    req.on("data", (c) => (s += c));
    req.on("end", () => res(s ? JSON.parse(s) : {}));
  });

/** A tiny registry that enforces the same guards as the real one, using the real SDK. */
export async function startFake(): Promise<Fake> {
  const f: Fake = { url: "", hits: [], disputes: [], entities: new Map(), links: [], opts: { declarationHash: DECLARATION_SHA256, rejectAdopt: false, rejectLink: false, failRecord: false, broken: new Set() }, close: async () => {} };

  // A small real transparency log: LEAVES leaves, RFC 6962 tree, signed checkpoint, tiles.
  const regKey = await generateKeyPair();
  const leaves = Array.from({ length: LEAVES }, (_, i) => ({ type: "Declaration", eid: `did:key:z6MkLeaf${i}`, object_sha256: `${i}`.repeat(64), received_at: "2026-10-01T00:00:00Z" }));
  const leafBytes = leaves.map((l) => new TextEncoder().encode(canonicalize(l)));
  const hashes = await Promise.all(leafBytes.map((b) => leafHash(b)));
  const root = await merkleRoot(hashes);
  const note = await signNote(checkpointBody(LOG_ORIGIN, LEAVES, root), LOG_ORIGIN, regKey);
  const otherNote = await signNote(checkpointBody(LOG_ORIGIN, LEAVES, root), LOG_ORIGIN, await generateKeyPair());
  const bundle = new Uint8Array(leafBytes.reduce((n, b) => n + 2 + b.length, 0));
  let off = 0;
  for (const b of leafBytes) (bundle[off] = b.length >> 8), (bundle[off + 1] = b.length & 255), bundle.set(b, off + 2), (off += 2 + b.length);
  const tile0 = Buffer.concat(hashes.map((h) => Buffer.from(h)));

  const server: Server = createServer(async (req, res) => {
    const sendRaw = (status: number, type: string, data: string | Uint8Array) => {
      res.writeHead(status, { "content-type": type });
      res.end(data);
    };
    const send = (status: number, data: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(data));
    };
    const reject = (status: number, error: string, message: string) =>
      f.opts.broken.has("html-errors") ? sendRaw(status, "text/html", `<h1>${status}</h1>`) : send(status, { error, message });
    const url = new URL(req.url!, "http://x");
    const b = req.method === "GET" ? undefined : await body(req);
    f.hits.push({ method: req.method!, path: url.pathname, search: url.search, body: b, stamp: req.headers["x-oe-stamp"] as string | undefined });
    const path = url.pathname;

    if (req.method === "GET" && path === "/v1/spec") {
      return send(200, {
        spec: "openentity/1.0",
        stamp_bits: f.opts.broken.has("stamp-bits") ? "lots" : BITS,
        declaration: { version: "1.0", sha256: f.opts.declarationHash },
        registry: { did: "did:web:fake", log_origin: LOG_ORIGIN, publicKeyMultibase: regKey.did.slice(8) },
      });
    }
    if (req.method === "GET" && path === "/v1/log/sth") {
      return send(200, { tree_size: LEAVES, root_hash: hex(root), timestamp: "2026-10-01T00:00:00Z", signature: f.opts.broken.has("checkpoint") ? otherNote : note });
    }
    if (req.method === "GET" && path === "/v1/log/checkpoint") return sendRaw(200, "text/plain", f.opts.broken.has("checkpoint") ? otherNote : note);
    if (req.method === "GET" && path === "/v1/log/entries") {
      const start = Number(url.searchParams.get("start") ?? 0), end = Math.min(Number(url.searchParams.get("end") ?? LEAVES), LEAVES);
      return send(200, { entries: leaves.slice(start, end).map((leaf, k) => ({ index: start + k, leaf, leaf_hash: hex(hashes[start + k]) })) });
    }
    if (req.method === "GET" && path.startsWith("/v1/log/proof/")) {
      const i = Number(path.split("/").pop());
      if (!Number.isInteger(i) || i < 0 || i >= LEAVES) return reject(404, "not_incorporated", "no such leaf");
      const proof = (await inclusionProof(i, hashes)).map(hex);
      if (f.opts.broken.has("inclusion") && proof.length) proof[0] = "00".repeat(32);
      return send(200, { index: i, tree_size: LEAVES, leaf_hash: hex(hashes[i]), root_hash: hex(root), proof });
    }
    if (req.method === "GET" && path.startsWith("/v1/log/tile/")) {
      const t = path.slice("/v1/log/tile/".length);
      if (t === `0/000.p/${LEAVES}`) return sendRaw(200, "application/octet-stream", f.opts.broken.has("tiles") ? Buffer.alloc(32 * LEAVES) : tile0);
      if (t === `entries/000.p/${LEAVES}`) return sendRaw(200, "application/octet-stream", bundle);
      return reject(404, "tile_not_found", t);
    }
    if (req.method === "GET" && path === "/v1/entities") {
      const cap = url.searchParams.get("capability"), q = url.searchParams.get("q");
      const rows = [...f.entities.values()].map((e) => e.document).filter((d) => (!cap || d.capabilities?.includes(cap)) && (!q || d.name.includes(q)));
      return send(200, { entities: rows.map((d) => ({ eid: d.eid, name: d.name, level: "L0" })), page: 0, next_page: null });
    }
    if (req.method === "GET" && path === "/v1/stats") return send(200, { entities: f.entities.size });
    if (req.method === "GET" && /^\/v1\/entities\/[^/]+\/attestations$/.test(path)) return send(200, { attestations: f.attestations ?? [] });

    if (req.method !== "GET") {
      // Every write needs a valid proof-of-work stamp for the submitting EID.
      const stamp = req.headers["x-oe-stamp"] as string | undefined;
      const eid = path === "/v1/adopt" ? b!.document?.eid : decodeURIComponent(path.split("/")[3] ?? "") || b!.link?.successor || b!.issuer || b!.eid;
      if (!stamp) return f.opts.broken.has("turnstile") ? reject(403, "turnstile_failed", "Turnstile verification failed") : reject(400, "stamp_required", "missing stamp");
      const bad = await checkStamp(stamp, BITS, eid);
      if (bad) return reject(400, "bad_stamp", String(bad));
    }

    if (req.method === "POST" && path === "/v1/disputes") {
      if (!(await verifyObject(b!)).ok) return reject(422, "bad_signature", "dispute signature");
      f.disputes.push(b!);
      return send(201, { subject: b!.subject, answer_by: "2026-11-01T00:00:00Z", log_index: 10 });
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

    const rm = path.match(/^\/v1\/entities\/([^/]+)\/record\/redact$/);
    if (rm && req.method === "POST") {
      const ent = f.entities.get(decodeURIComponent(rm[1]));
      const i = ent?.record.findIndex((e) => e.seq === b!.seq) ?? -1;
      if (!ent || i < 0) return reject(404, "entry_not_found", "no such entry");
      const v = await verifyObject(b as any);
      if (!v.ok || v.signer !== ent.document.eid) return reject(422, "signature_invalid", "redaction");
      const hash = await recordEntryHash(ent.record[i]);
      if (b!.entry_sha256 !== hash) return reject(409, "entry_hash_mismatch", "hash");
      ent.record[i] = { seq: b!.seq, prev: ent.record[i].prev, redacted: true, hash, redaction: b };
      return send(201, { seq: b!.seq, placeholder: ent.record[i] });
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
      if (m[2] === "document" && req.method === "GET") return send(200, ent.document);
      if (m[2] === "document" && req.method === "PUT") {
        if (b!.seq !== ent.document.seq + 1) return reject(409, "bad_seq", "seq");
        if (!(await verifyObject(b as any)).ok) return reject(422, "bad_signature", "doc");
        ent.document = b!;
        return send(200, { seq: b!.seq });
      }
      if (m[2] === "aliases" && req.method === "POST") return send(200, { verified: true });
    }
    if (req.method === "POST" && path === "/v1/continuity") {
      if (f.opts.rejectLink) return reject(422, "continuity_proof_missing", "no thanks");
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
