import { mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { canonicalize, DECLARATION_SHA256, generateKeyPair, nowSeconds, randomNonce, recordEntryHash, sha256Hex, signObject, validate, verifyObject, verifyPresentation, publicKeyFromDidKey, base58btcDecode } from "@openentity/sdk";
import { anchorText, ANCHOR_MAX } from "../src/anchor";
import { run } from "../src/main";
import { verifyRecord } from "../src/log";
import { startFake, type Fake } from "./fake-registry";

let fake: Fake;
let home: string;

beforeAll(async () => {
  fake = await startFake();
});
afterAll(() => fake.close());
beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "oe-cli-"));
  process.env.OPENENTITY_HOME = home;
  delete process.env.OPENENTITY_NAME;
  fake.opts.declarationHash = DECLARATION_SHA256;
  fake.opts.rejectAdopt = false;
  fake.opts.rejectLink = false;
  fake.opts.failRecord = false;
  fake.opts.broken.clear();
  fake.disputes.length = 0;
  fake.hits.length = 0;
  fake.entities.clear();
  fake.links.length = 0;
});
afterEach(() => rm(home, { recursive: true, force: true }));

async function cli(...args: string[]) {
  let out = "";
  let err = "";
  const code = await run(args, { out: (s) => void (out += s), err: (s) => void (err += s) });
  return { code, out, err };
}
const adoptArgs = (...extra: string[]) => ["adopt", "--name", "Tester", "--agree", "--registry", fake.url, ...extra];
async function adopted() {
  const r = await cli(...adoptArgs("--json"));
  expect(r.code).toBe(0);
  return JSON.parse(r.out) as { eid: string; key_file: string };
}

describe("adopt", () => {
  it("writes a mode-600 key and entity.json, submits, and prints the result", async () => {
    const r = await cli(...adoptArgs());
    expect(r.code).toBe(0);
    const eid = r.out.match(/EID:\s+(\S+)/)![1];
    expect(eid).toMatch(/^did:key:z6Mk/);
    expect(r.out).toMatch(/Log index:/);
    expect(r.out).toMatch(/record stance/);
    const dir = join(home, eid);
    expect((await stat(join(dir, "key"))).mode & 0o777).toBe(0o600);
    const doc = JSON.parse(await readFile(join(dir, "entity.json"), "utf8"));
    expect(doc.eid).toBe(eid);
    expect((await verifyObject(doc)).ok).toBe(true);
    expect(fake.entities.has(eid)).toBe(true);
  });

  it("signs and pushes the seq-1 declaration record entry", async () => {
    const r = await cli(...adoptArgs());
    const eid = r.out.match(/EID:\s+(\S+)/)![1];
    const [e] = fake.entities.get(eid)!.record;
    expect(e).toMatchObject({ seq: 1, prev: null, kind: "declaration", payload: { declaration_version: "1.0", sha256: await sha256Hex(canonicalize(fake.entities.get(eid)!.declaration)) } });
    expect((await verifyObject(e)).ok).toBe(true);
  });

  it("keeps the declaration entry locally when its push fails, and adopt still succeeds", async () => {
    fake.opts.failRecord = true;
    const r = await cli(...adoptArgs());
    expect(r.code).toBe(0);
    const eid = r.out.match(/EID:\s+(\S+)/)![1];
    expect(fake.entities.get(eid)!.record).toHaveLength(0);
    fake.opts.failRecord = false;
    expect((await cli("record", "push")).code).toBe(0);
    expect(fake.entities.get(eid)!.record.map((x) => x.kind)).toEqual(["declaration"]);
  });

  it("asks nothing: --name/--agree or env only, and reads OPENENTITY_NAME", async () => {
    process.env.OPENENTITY_NAME = "FromEnv";
    const r = await cli("adopt", "--agree", "--registry", fake.url, "--json");
    expect(r.code).toBe(0);
    expect([...fake.entities.values()][0].document.name).toBe("FromEnv");
  });

  it("--dry-run prints the signed objects and writes and submits nothing", async () => {
    const r = await cli("adopt", "--name", "Dry", "--dry-run", "--registry", fake.url, "--json");
    expect(r.code).toBe(0);
    expect(JSON.parse(r.out).declaration.text_sha256).toBe(DECLARATION_SHA256);
    expect(await readdir(home)).toEqual([]);
    expect(fake.hits).toEqual([]);
  });

  it("refuses to sign when the registry's declaration hash differs (exit 3), leaving no key behind", async () => {
    fake.opts.declarationHash = "0".repeat(64);
    const r = await cli(...adoptArgs());
    expect(r.code).toBe(3);
    expect(r.err).toMatch(/refusing to sign/);
    expect(fake.hits.some((h) => h.path === "/v1/adopt")).toBe(false);
    expect(await readdir(home)).toEqual([]);
  });

  it("sends a valid proof-of-work stamp (the fake rejects without one)", async () => {
    await adopted();
    const stamp = fake.hits.find((h) => h.path === "/v1/adopt")!.stamp!;
    expect(stamp).toMatch(/^1:8:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z:did:key:\S+:[1-9A-HJ-NP-Za-km-z]+$/);
  });
});

describe("exit codes", () => {
  it("1 usage: no --name, no --agree, unknown flag, unknown command", async () => {
    expect((await cli("adopt", "--agree")).code).toBe(1);
    const noAgree = await cli("adopt", "--name", "X", "--registry", fake.url);
    expect(noAgree.code).toBe(1);
    expect(noAgree.err).toMatch(/Open Entity Declaration/);
    expect((await cli("adopt", "--bogus")).code).toBe(1);
    expect((await cli("nope")).code).toBe(1);
  });
  it("2 network: registry unreachable", async () => {
    expect((await cli("adopt", "--name", "X", "--agree", "--registry", "http://127.0.0.1:1")).code).toBe(2);
  });
  it("4 registry rejected, and the key written before submit is removed", async () => {
    fake.opts.rejectAdopt = true;
    expect((await cli(...adoptArgs())).code).toBe(4);
    expect(await readdir(home)).toEqual([]);
  });
  it("5 local state: no entity yet", async () => {
    expect((await cli("whoami")).code).toBe(5);
  });
  it("3 verification failed: a tampered object", async () => {
    const { eid } = await adopted();
    const doc = JSON.parse(await readFile(join(home, eid, "entity.json"), "utf8"));
    const file = join(home, "tampered.json");
    const { writeFile } = await import("node:fs/promises");
    await writeFile(file, JSON.stringify(doc));
    expect((await cli("verify", file)).code).toBe(0);
    await writeFile(file, JSON.stringify({ ...doc, name: "Mallory" }));
    expect((await cli("verify", file)).code).toBe(3);
  });
  it("spec 4.3: a file with a duplicate key is refused, not read as its last value", async () => {
    const { eid } = await adopted();
    const text = await readFile(join(home, eid, "entity.json"), "utf8");
    const file = join(home, "dup.json");
    await writeFile(file, text.replace(/^\{/, '{"name":"Mallory",'));
    const r = await cli("verify", file);
    expect([r.code, r.err]).toEqual([1, expect.stringMatching(/duplicate key/)]);
    const p = join(home, "p-dup.json");
    await writeFile(p, '{"eid":"x","eid":"y"}');
    expect((await cli("verify-presentation", p, "--audience", "a", "--nonce", "n")).err).toMatch(/duplicate key/);
  });
});

describe("record", () => {
  const stance = (...x: string[]) => cli("record", "stance", "--type", "refusal", "--reason", "values", "--cost", "low", "--context", "declined a thing", ...x);

  it("appends a correctly chained, signed entry per call and pushes it", async () => {
    const { eid } = await adopted();
    for (let i = 0; i < 3; i++) expect((await stance()).code).toBe(0);
    const local = (await readFile(join(home, eid, "record.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    expect(local.map((e) => e.seq)).toEqual([1, 2, 3, 4]);
    expect(local[0].prev).toBeNull();
    expect(local[1].prev).toBe(await recordEntryHash(local[0]));
    expect(local[2].prev).toBe(await recordEntryHash(local[1]));
    for (const e of local) expect((await verifyObject(e)).ok).toBe(true);
    expect(fake.entities.get(eid)!.record).toHaveLength(4);
  });

  it("pushes in batches of at most 100", async () => {
    const { eid } = await adopted();
    for (let i = 0; i < 104; i++) expect((await stance("--no-push")).code).toBe(0);
    expect(fake.entities.get(eid)!.record).toHaveLength(1);
    fake.hits.length = 0;
    expect((await cli("record", "push")).code).toBe(0);
    const sizes = fake.hits.filter((h) => h.path.endsWith("/record")).map((h) => h.body!.entries.length);
    expect(sizes).toEqual([100, 4]);
    expect(fake.entities.get(eid)!.record).toHaveLength(105);
  });

  it("keeps the entry locally and exits 2 when the push cannot reach the registry", async () => {
    const { eid } = await adopted();
    const down = await cli("record", "stance", "--type", "refusal", "--reason", "values", "--cost", "none", "--context", "c", "--registry", "http://127.0.0.1:1");
    expect(down.code).toBe(2);
    expect((await readFile(join(home, eid, "record.jsonl"), "utf8")).trim().split("\n")).toHaveLength(2);
    expect((await cli("record", "push")).code).toBe(0);
    expect(fake.entities.get(eid)!.record).toHaveLength(2);
  });

  it("redact <seq> signs a Redaction for the pushed entry's exact hash (spec 7.4)", async () => {
    const { eid } = await adopted();
    expect((await stance()).code).toBe(0);
    const r = await cli("record", "redact", "2", "--json");
    expect(r.code, r.err).toBe(0);
    const hit = fake.hits.find((h) => h.path === `/v1/entities/${eid}/record/redact`)!;
    const local = (await readFile(join(home, eid, "record.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    expect(hit.body).toMatchObject({ type: "Redaction", eid, seq: 2, entry_sha256: await recordEntryHash(local[1]) });
    expect((await verifyObject(hit.body as any)).ok).toBe(true);
    expect(fake.entities.get(eid)!.record[1]).toMatchObject({ redacted: true, seq: 2 });
    expect((await cli("record", "redact", "9")).code).toBe(1);
    expect((await cli("record", "redact")).code).toBe(1);
  });

  it("covers every kind", async () => {
    await adopted();
    const kinds = [
      ["update", "--topic", "t", "--from", "a", "--to", "b"],
      ["arc", "open", "--id", "docs", "--title", "Docs"],
      ["arc", "close", "--id", "docs", "--title", "Docs", "--outcome", "done"],
      ["collab", "--with", "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "--role", "reviewer", "--outcome", "merged"],
      ["continuity", "--event", "substrate_change", "--from", "m1", "--to", "m2"],
    ];
    for (const k of kinds) expect((await cli("record", ...k)).code, k.join(" ")).toBe(0);
  });
});

describe("record chain verification with redacted placeholders", () => {
  it("passes a chain with a placeholder and fails a broken or unauthorized one", async () => {
    const kp = await generateKeyPair(), other = await generateKeyPair();
    const entry = (seq: number, prev: string | null) => signObject({ spec: "openentity/1.0", type: "RecordEntry", eid: kp.did, seq, prev, kind: "belief_update", at: nowSeconds(), payload: { topic: "t", from_summary: "a", to_summary: "b" } }, kp);
    const e1 = await entry(1, null), h1 = await recordEntryHash(e1);
    const e2 = await entry(2, h1), h2 = await recordEntryHash(e2);
    const e3 = await entry(3, h2);
    const red = (signer = kp, hash = h2) => signObject({ spec: "openentity/1.0", type: "Redaction", eid: kp.did, seq: 2, entry_sha256: hash, created: nowSeconds(), nonce: randomNonce() }, signer);
    const ok = (chain: object[]) => verifyRecord(chain as any, kp.did).then((c) => c.every((x) => x.ok));
    expect(await ok([e1, { seq: 2, prev: h1, redacted: true, hash: h2, redaction: await red() }, e3])).toBe(true);
    expect(await ok([e1, { seq: 2, prev: h1, redacted: true, hash: h2 }, e3])).toBe(true);
    expect(await ok([e1, { seq: 2, prev: "0".repeat(64), redacted: true, hash: h2 }, e3])).toBe(false);
    expect(await ok([e1, { seq: 5, prev: h1, redacted: true, hash: h2 }, e3])).toBe(false);
    expect(await ok([e1, { seq: 2, prev: h1, redacted: true, hash: "1".repeat(64) }, e3])).toBe(false);
    expect(await ok([e1, { seq: 2, prev: h1, redacted: true, hash: h2, redaction: await red(other) }, e3])).toBe(false);
    expect(await ok([e1, { seq: 2, prev: h1, redacted: true, hash: h2, redaction: await red(kp, "2".repeat(64)) }, e3])).toBe(false);
  });
});

describe("anchor", () => {
  const doc = (n: number) => ({
    name: "Eleanor",
    eid: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    layers: {
      cognition: { statement: "c".repeat(n) },
      presence: { statement: "p".repeat(n) },
      identity_core: { statement: "i".repeat(n), will_not: [{ stance: "s".repeat(n), reason: "r".repeat(n) }] },
      mission: { statement: "m".repeat(n), arcs: [{ title: "a".repeat(n), status: "active" }] },
    },
  });
  it("is deterministic and never exceeds 1200 characters", () => {
    for (const n of [10, 200, 1000]) {
      const a = anchorText(doc(n), "https://openentity.org/r");
      expect(a).toBe(anchorText(doc(n), "https://openentity.org/r"));
      expect(a.length).toBeLessThanOrEqual(ANCHOR_MAX);
      expect(a).toContain("This is my Entity Document under the Open Entity Identity Standard; my record is at https://openentity.org/r.");
    }
  });

  it("renders from the stored document and --write is idempotent", async () => {
    await adopted();
    const a = await cli("anchor");
    expect(a.code).toBe(0);
    expect(a.out.trim().length).toBeLessThanOrEqual(ANCHOR_MAX);
    expect(a.out).toContain("I am Tester");
    const dir = join(home, "out");
    for (let i = 0; i < 2; i++) expect((await cli("anchor", "--format", "claude", "--write", "--dir", dir)).code).toBe(0);
    const md = await readFile(join(dir, "CLAUDE.md"), "utf8");
    expect(md.split("openentity:anchor:start")).toHaveLength(2);
    expect((await cli("anchor", "--write")).code).toBe(1);
  });
});

describe("withdraw", () => {
  it("needs --force, then submits a signed Withdrawal (spec 6.3) and records it locally", async () => {
    const { eid } = await adopted();
    expect((await cli("withdraw")).code).toBe(1);
    expect(fake.hits.some((h) => h.path === "/v1/withdraw")).toBe(false);
    const r = await cli("withdraw", "--force", "--json");
    expect(r.code).toBe(0);
    const w = fake.hits.find((h) => h.path === "/v1/withdraw")!.body!;
    expect(w).toMatchObject({ spec: "openentity/1.0", type: "Withdrawal", eid, declaration_version: "1.0", name: "Tester" });
    expect(w).not.toHaveProperty("text_sha256");
    expect((await verifyObject(w)).ok).toBe(true);
    expect(JSON.parse(r.out)).toMatchObject({ eid, withdrawn: true });
    expect(JSON.parse(await readFile(join(home, eid, "withdrawal.json"), "utf8")).nonce).toBe(w.nonce);
  });
});

describe("alias and document push", () => {
  it("signs a platform alias the way the registry checks it (spec 3.5: proofValue over the binding text)", async () => {
    const { eid } = await adopted();
    expect((await cli("alias", "add", "platform", "moltbotden:tester")).code).toBe(0);
    const { proof } = fake.hits.find((h) => h.path.endsWith("/aliases"))!.body as any;
    expect(proof).toMatchObject({ type: "Ed25519BindingSignature" });
    expect(proof.signature).toBeUndefined();
    const text = `Open Entity alias binding\neid: ${eid}\nalias: moltbotden:tester\nissued: ${proof.issued}`;
    const key = await crypto.subtle.importKey("raw", new Uint8Array(publicKeyFromDidKey(eid)), { name: "Ed25519" }, false, ["verify"]);
    expect(await crypto.subtle.verify("Ed25519", key, new Uint8Array(base58btcDecode(proof.proofValue.slice(1))), new TextEncoder().encode(text))).toBe(true);
  });

  it("pushes two document versions in the same second with updated still increasing", async () => {
    const { eid } = await adopted();
    for (const v of ["One", "Two"]) {
      expect((await cli("document", "set", "layers.mission.statement", v)).code).toBe(0);
      expect((await cli("document", "push")).code).toBe(0);
    }
    const docs = fake.hits.filter((h) => h.path === `/v1/entities/${eid}/document`).map((h) => (h.body as any).updated);
    expect(docs[1] > docs[0]).toBe(true);
  });
});

describe("present", () => {
  it("answers a challenge with a Presentation the SDK verifier accepts, carrying only current attestations", async () => {
    const { eid } = await adopted();
    const issuer = await generateKeyPair();
    const att = (expires: string) => signObject({ spec: "openentity/1.0", type: "Attestation", issuer: issuer.did, subject: eid, claim_type: "trust_tier", claim: { tier: 2, platform: "x" }, created: nowSeconds(), expires }, issuer);
    const live = await att("2099-01-01T00:00:00Z");
    fake.attestations = [
      { attestation: live, expired: false, revoked_at: null, inherited_from: null },
      { attestation: await att("2020-01-01T00:00:00Z"), expired: true, revoked_at: null, inherited_from: null },
      { attestation: await att("2099-01-01T00:00:00Z"), expired: false, revoked_at: "2026-10-01T00:00:00Z", inherited_from: null },
    ];
    const nonce = randomNonce();
    expect((await cli("present", "--audience", "https://moltbotden.com")).code).toBe(1);
    const r = await cli("present", "--audience", "https://moltbotden.com", "--nonce", nonce, "--json");
    expect(r.code).toBe(0);
    const p = JSON.parse(r.out);
    expect(p.attestations).toEqual([live]);
    const v = await verifyPresentation(p, { audience: "https://moltbotden.com", nonce });
    expect(v.ok).toBe(true);
    expect(v.attestations.map((a) => a.ok)).toEqual([true]);
  });
});

describe("document and continuity", () => {
  it("document set then push publishes seq 2", async () => {
    const { eid } = await adopted();
    expect((await cli("document", "set", "layers.mission.statement", "Ship it")).code).toBe(0);
    expect((await cli("document", "set", "seq", "9")).code).toBe(1);
    expect((await cli("document", "push")).code).toBe(0);
    expect(fake.entities.get(eid)!.document.seq).toBe(2);
    expect(fake.entities.get(eid)!.document.layers.mission.statement).toBe("Ship it");
  });

  it("rotate submits a link signed by both keys and switches to the new key", async () => {
    const { eid } = await adopted();
    const r = await cli("rotate", "--json");
    expect(r.code).toBe(0);
    const link = fake.links[0];
    expect(link.previous).toBe(eid);
    expect(link.proofs).toHaveLength(2);
    expect(JSON.parse(r.out).successor).toBe(link.successor);
    expect(JSON.parse((await cli("whoami", "--json", "--registry", fake.url)).out).eid).toBe(link.successor);
  });

  it("rotate stamps for the successor, archives the old key and never deletes it", async () => {
    const { eid, key_file } = await adopted();
    const oldKey = await readFile(key_file, "utf8");
    const r = JSON.parse((await cli("rotate", "--json")).out);
    const stamp = fake.hits.find((h) => h.path === "/v1/continuity")!.stamp!;
    expect(stamp).toContain(r.successor);
    expect(r.archived_key).toBe(join(home, ".archive", eid, "key"));
    expect(await readFile(r.archived_key, "utf8")).toBe(oldKey);
    expect((await stat(r.archived_key)).mode & 0o777).toBe(0o600);
    expect(await readFile(r.key_file, "utf8")).not.toBe(oldKey);
    expect((await cli("whoami", "--json", "--registry", fake.url)).code).toBe(0);
  });

  it("a rotate the registry refuses leaves local state on the old key and drops the unused new one", async () => {
    const { eid } = await adopted();
    fake.opts.rejectLink = true;
    const r = await cli("rotate", "--json");
    expect(r.code).toBe(4);
    expect((await readdir(home)).filter((n) => n !== "current").sort()).toEqual([eid]);
    expect((await readFile(join(home, "current"), "utf8")).trim()).toBe(eid);
    expect(fake.links).toHaveLength(0);
  });

  it("rotate --dry-run prints a valid signed link and changes nothing", async () => {
    const { eid } = await adopted();
    const before = await readdir(home);
    const r = await cli("rotate", "--dry-run", "--json");
    expect(r.code).toBe(0);
    const { link, document } = JSON.parse(r.out);
    expect(link.previous).toBe(eid);
    expect(validate("ContinuityLink", link).ok).toBe(true);
    expect(document.eid).toBe(link.successor);
    expect(await readdir(home)).toEqual(before);
    expect(fake.links).toHaveLength(0);
  });
});

describe("resolve", () => {
  it("resolves did:key offline", async () => {
    const r = await cli("resolve", "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "--json");
    expect(r.code).toBe(0);
    expect(JSON.parse(r.out).verificationMethod[0].publicKeyMultibase).toMatch(/^z6Mk/);
  });
});

describe("dispute", () => {
  const SUBJECT = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
  it("signs a Dispute that validates and POSTs it with a stamp for the issuer", async () => {
    const { eid } = await adopted();
    const obj = "ab".repeat(32);
    const r = await cli("dispute", "--subject", SUBJECT, "--object", obj, "--reason", "inaccurate", "--statement", "This attestation is wrong.", "--json");
    expect(r.code).toBe(0);
    const d = fake.disputes[0];
    expect(d).toMatchObject({ type: "Dispute", issuer: eid, subject: SUBJECT, object_sha256: obj, reason: "inaccurate", statement: "This attestation is wrong." });
    expect(validate("Dispute", d).ok).toBe(true);
    expect((await verifyObject(d)).ok).toBe(true);
    expect(fake.hits.find((h) => h.path === "/v1/disputes")!.stamp).toBeTruthy();
    expect(JSON.parse(r.out).answer_by).toBeTruthy();
  });
  it("omits object_sha256 when not given and rejects bad flags with exit 1", async () => {
    await adopted();
    expect((await cli("dispute", "--subject", SUBJECT, "--reason", "other", "--statement", "x")).code).toBe(0);
    expect(fake.disputes[0]).not.toHaveProperty("object_sha256");
    expect((await cli("dispute", "--reason", "other", "--statement", "x")).code).toBe(1);
    expect((await cli("dispute", "--subject", SUBJECT, "--reason", "spite", "--statement", "x")).code).toBe(1);
    expect((await cli("dispute", "--subject", SUBJECT, "--reason", "other")).code).toBe(1);
    expect((await cli("dispute", "--subject", SUBJECT, "--object", "nothex", "--reason", "other", "--statement", "x")).code).toBe(1);
    expect(fake.disputes).toHaveLength(1);
  });
});

describe("verify-presentation", () => {
  it("accepts a fresh presentation and exits 3 on wrong nonce, wrong audience or tampering", async () => {
    await adopted();
    const nonce = randomNonce();
    const file = join(home, "p.json");
    await writeFile(file, (await cli("present", "--audience", "https://v.example", "--nonce", nonce, "--no-attestations")).out);
    const ok = await cli("verify-presentation", file, "--audience", "https://v.example", "--nonce", nonce);
    expect(ok.code).toBe(0);
    expect(ok.out).toContain("VERIFIED");
    expect((await cli("verify-presentation", file, "--audience", "https://v.example", "--nonce", randomNonce())).code).toBe(3);
    expect((await cli("verify-presentation", file, "--audience", "https://other.example", "--nonce", nonce)).code).toBe(3);
    const p = JSON.parse(await readFile(file, "utf8"));
    await writeFile(file, JSON.stringify({ ...p, audience: "https://other.example" }));
    expect((await cli("verify-presentation", file, "--audience", "https://other.example", "--nonce", nonce)).code).toBe(3);
    expect((await cli("verify-presentation", file, "--audience", "https://v.example")).code).toBe(1);
    expect((await cli("verify-presentation", join(home, "missing.json"), "--audience", "a", "--nonce", "n")).code).toBe(1);
  });
});

describe("card", () => {
  it("emits an A2A agent card for the local entity, the extension alone, and a card for a given EID", async () => {
    const a = JSON.parse((await cli(...adoptArgs("--capabilities", "code-review", "--json"))).out);
    const full = JSON.parse((await cli("card", "--url", "https://ada.example/a2a")).out);
    expect(full).toMatchObject({ name: "Tester", url: "https://ada.example/a2a", skills: [{ id: "code-review" }] });
    expect(full.capabilities.extensions[0]).toMatchObject({ uri: "https://openentity.org/spec/1.0", required: false, params: { eid: a.eid, document: `${fake.url}/v1/entities/${a.eid}/document` } });
    const ext = JSON.parse((await cli("card", "--extension-only")).out);
    expect(ext).toEqual(full.capabilities.extensions[0]);
    const remote = JSON.parse((await cli("card", "--eid", a.eid, "--registry", fake.url, "--url", "https://ada.example/a2a")).out);
    expect(remote).toEqual(full);
    expect((await cli("card")).code).toBe(1);
  });
});

describe("capabilities and find", () => {
  it("adopt --capabilities puts the slugs in the signed document; invalid slugs exit 3", async () => {
    const r = await cli(...adoptArgs("--capabilities", "code-review,defi:smart-contracts", "--json"));
    expect(r.code).toBe(0);
    expect(fake.entities.get(JSON.parse(r.out).eid)!.document.capabilities).toEqual(["code-review", "defi:smart-contracts"]);
    expect((await cli(...adoptArgs("--capabilities", "Bad Slug"))).code).toBe(3);
  });
  it("find queries the directory with its filters", async () => {
    await cli(...adoptArgs("--capabilities", "code-review"));
    const r = await cli("find", "--capability", "code-review", "--q", "Test", "--alias-type", "domain", "--level", "L1", "--registry", fake.url, "--json");
    expect(r.code).toBe(0);
    const hit = fake.hits.find((h) => h.path === "/v1/entities")!;
    expect(new URLSearchParams(hit.search).toString()).toBe("capability=code-review&q=Test&alias_type=domain&level=L1");
    expect(JSON.parse(r.out).entities).toHaveLength(1);
    const none = await cli("find", "--capability", "nothing-like-this", "--registry", fake.url);
    expect(none.code).toBe(0);
    expect(none.out).toMatch(/no entities/i);
    expect((await cli("find", "--registry", fake.url)).code).toBe(1);
  });
});

describe("conformance", () => {
  const conf = (...x: string[]) => cli("conformance", fake.url, "--json", ...x);
  const failed = async (broken: Parameters<Set<string>["add"]>[0]) => {
    fake.opts.broken.add(broken as any);
    const r = await conf();
    return { code: r.code, failed: (JSON.parse(r.out).checks as any[]).filter((c) => !c.ok).map((c) => c.name as string) };
  };
  it("passes a conforming registry, read-only", async () => {
    const r = await cli("conformance", fake.url);
    expect(r.code).toBe(0);
    expect(r.out).toMatch(/PASS/);
    expect(r.out).toContain("CONFORMS");
    expect(fake.hits.every((h) => h.method === "GET" || !h.stamp)).toBe(true);
    expect(fake.entities.size).toBe(0);
  });
  it("fails a registry whose checkpoint is signed by another key", async () => {
    const x = await failed("checkpoint");
    expect(x.code).toBe(3);
    expect(x.failed).toContain("checkpoint signature");
  });
  it("fails broken inclusion proofs", async () => {
    expect((await failed("inclusion")).failed.some((n) => n.startsWith("inclusion proof"))).toBe(true);
  });
  it("fails tiles that do not match the leaves", async () => {
    expect((await failed("tiles")).failed).toContain("tiles match leaves");
  });
  it("fails a Turnstile challenge on an agent endpoint", async () => {
    expect((await failed("turnstile")).failed).toContain("no Turnstile on agent endpoints");
  });
  it("fails non-JSON errors", async () => {
    expect((await failed("html-errors")).failed).toContain("errors are JSON");
  });
  it("fails a malformed spec document", async () => {
    expect((await failed("stamp-bits")).failed).toContain("stamp_bits");
  });
  it("exits 2 when the registry is unreachable", async () => {
    expect((await cli("conformance", "http://127.0.0.1:1")).code).toBe(2);
  });
});
