import { base58btcDecode, canonicalize, leafHash, verifyNote } from "@openentity/sdk";
import { CliError, EXIT, usage } from "./errors";
import { checkpointCheck, inclusionCheck } from "./log";
import { Registry, type Obj } from "./http";
import { regUrl, type Ctx, type Result } from "./store";

interface Check {
  name: string;
  ok: boolean;
  detail: string;
}
interface Reply {
  status: number;
  json: boolean;
  body: any;
  raw: Buffer;
}

/** Any HTTP answer, 4xx and 5xx included. Only an unreachable registry throws. */
async function probe(base: string, path: string, init: RequestInit = {}): Promise<Reply> {
  let res: Response;
  try {
    res = await fetch(base + path, { ...init, headers: { "user-agent": "openentity-conformance", ...(init.headers as Obj) }, signal: AbortSignal.timeout(30_000) });
  } catch (e: any) {
    throw new CliError(EXIT.NETWORK, `network error: ${init.method ?? "GET"} ${base + path}: ${e?.cause?.message ?? e.message}`);
  }
  const raw = Buffer.from(await res.arrayBuffer());
  const json = (res.headers.get("content-type") ?? "").includes("json");
  let body: any = raw.toString("utf8");
  if (json) {
    try {
      body = JSON.parse(body);
    } catch {
      /* declared JSON, not JSON: the checks that read body fail on it */
    }
  }
  return { status: res.status, json, body, raw };
}

/** Run one check; a throw is a failure, not a crash. */
async function check(name: string, fn: () => Promise<string>): Promise<Check> {
  try {
    return { name, ok: true, detail: await fn() };
  } catch (e: any) {
    return { name, ok: false, detail: e.message };
  }
}
const must = (cond: unknown, msg: string) => {
  if (!cond) throw new Error(msg);
};

const TILE_WIDTH = 256;
const tilePath = (kind: string, width: number) => `/v1/log/tile/${kind}/000${width < TILE_WIDTH ? `.p/${width}` : ""}`;

/** The read-only checks any registry must pass (spec 10). Writes are only ever sent without a stamp, so nothing is stored. */
export async function conformance({ args, v }: Ctx): Promise<Result> {
  const target = args[0] ?? v.registry;
  if (!target) throw usage("conformance <registry-url>");
  const base = regUrl({ registry: target }).replace(/\/+$/, "");
  const reg = new Registry(base);
  const checks: Check[] = [];

  const first = await probe(base, "/v1/spec"); // throws NETWORK when unreachable
  const spec: Obj = first.body && typeof first.body === "object" ? first.body : {};
  checks.push(
    await check("spec endpoint", async () => {
      must(first.status === 200 && first.json, `GET /v1/spec answered ${first.status}${first.json ? "" : " (not JSON)"}`);
      must(spec.spec === "openentity/1.0", `spec is ${JSON.stringify(spec.spec)}, expected "openentity/1.0"`);
      must(/^[0-9a-f]{64}$/.test(spec.declaration?.sha256 ?? ""), "declaration.sha256 is not 64 hex characters");
      must(typeof spec.registry?.publicKeyMultibase === "string", "registry.publicKeyMultibase missing");
      must(typeof spec.registry?.log_origin === "string", "registry.log_origin missing");
      return `declaration ${spec.declaration.sha256.slice(0, 12)}, origin ${spec.registry.log_origin}`;
    }),
    await check("stamp_bits", async () => {
      must(Number.isInteger(spec.stamp_bits) && spec.stamp_bits >= 1 && spec.stamp_bits <= 32, `stamp_bits is ${JSON.stringify(spec.stamp_bits)}, expected an integer from 1 to 32`);
      return `${spec.stamp_bits} bits`;
    }),
  );

  const cp = await checkpointCheck(reg).catch((e: any) => ({ ok: false, detail: e.message, sth: {} as Obj }));
  checks.push(
    await check("checkpoint signature", async () => {
      must(cp.ok, cp.detail);
      const pk = base58btcDecode(spec.registry.publicKeyMultibase.slice(1)).slice(-32);
      const note = (await probe(base, "/v1/log/checkpoint")).raw.toString("utf8");
      must(await verifyNote(note, spec.registry.log_origin, pk), "GET /v1/log/checkpoint does not verify against the published key");
      return cp.detail;
    }),
  );

  const size: number = cp.sth.tree_size ?? 0;
  if (cp.ok && size > 0) {
    const sample = [...new Set([0, Math.floor(size / 4), Math.floor(size / 2), Math.floor((3 * size) / 4), size - 1])];
    for (const i of sample) {
      checks.push(
        await check(`inclusion proof ${i}`, async () => {
          const r = await inclusionCheck(reg, i, cp.sth);
          must(r.ok, r.detail);
          return r.detail;
        }),
      );
    }
    checks.push(
      await check("tiles match leaves", async () => {
        const w = Math.min(size, TILE_WIDTH);
        const { entries } = await reg.get(`/v1/log/entries?start=0&end=${w}`);
        must(entries?.length === w, `expected ${w} log entries, got ${entries?.length}`);
        const leaves: Buffer[] = entries.map((e: Obj) => Buffer.from(canonicalize(e.leaf)));
        const hashes = Buffer.concat(await Promise.all(leaves.map(async (l) => Buffer.from(await leafHash(l)))));
        const t0 = await probe(base, tilePath("0", w));
        must(t0.status === 200, `hash tile answered ${t0.status}`);
        must(t0.raw.equals(hashes), "hash tile 0/000 differs from the leaf hashes");
        const eb = await probe(base, tilePath("entries", w));
        must(eb.status === 200, `entry bundle answered ${eb.status}`);
        let off = 0;
        for (const [k, l] of leaves.entries()) {
          const len = eb.raw.readUInt16BE(off);
          must(eb.raw.subarray(off + 2, off + 2 + len).equals(l), `entry bundle leaf ${k} differs from /v1/log/entries`);
          off += 2 + len;
        }
        must(off === eb.raw.length, "entry bundle has trailing bytes");
        return `${w} hashes and entries match`;
      }),
    );
  }

  checks.push(
    await check("errors are JSON", async () => {
      for (const path of ["/v1/entities/did:key:z6MkConformanceNoSuchEntity00000000000000", "/v1/log/proof/999999999"]) {
        const r = await probe(base, path);
        must(r.status >= 400 && r.status < 500, `GET ${path} answered ${r.status}, expected a 4xx`);
        must(r.json && typeof r.body?.error === "string", `GET ${path} error body is not {"error": ...} JSON`);
      }
      return "4xx answers carry {error, message}";
    }),
    await check("no Turnstile on agent endpoints", async () => {
      for (const path of ["/v1/adopt", "/v1/disputes", "/v1/withdraw"]) {
        const r = await probe(base, path, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
        must(r.status === 400 && r.body?.error === "stamp_required", `POST ${path} without a stamp answered ${r.status} ${r.json ? r.body?.error : "(not JSON)"}, expected 400 stamp_required`);
      }
      return "stampless writes answer stamp_required";
    }),
  );

  const failed = checks.filter((c) => !c.ok).length;
  const w = Math.max(...checks.map((c) => c.name.length));
  const text = [
    ...checks.map((c) => `${c.ok ? "PASS" : "FAIL"}  ${c.name.padEnd(w)}  ${c.detail}`),
    failed ? `DOES NOT CONFORM: ${failed} of ${checks.length} checks failed` : `CONFORMS: ${checks.length} checks passed`,
  ].join("\n");
  return { json: { registry: base, ok: !failed, checks }, text, code: failed ? EXIT.VERIFY : 0 };
}
