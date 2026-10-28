import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { Validator } from "@cfworker/json-schema";
import { hashTypedData, recoverTypedDataAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import * as oe from "../src/index.ts";
import { buildVectors, serialize } from "../scripts/gen-vectors.ts";

const root = new URL("../../../", import.meta.url);
const read = (p: string) => readFileSync(new URL(p, root));
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (h: string) => Uint8Array.from(h.match(/../g)!, (x) => parseInt(x, 16));
const seed = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const NOW = new Date("2026-10-24T19:00:00Z");

describe("encoding", () => {
  it("canonicalize follows RFC 8785", () => {
    expect(oe.canonicalize({ b: 1, a: [true, null, "x"], c: { z: 1, y: 2 } })).toBe('{"a":[true,null,"x"],"b":1,"c":{"y":2,"z":1}}');
    expect(oe.canonicalize({ n: 1e21, m: 0.000001, k: -0, f: 1.5 })).toBe('{"f":1.5,"k":0,"m":0.000001,"n":1e+21}');
    expect(oe.canonicalize({ "\u20ac": 1, "\r": 2, "1": 3 })).toBe('{"\\r":2,"1":3,"\u20ac":1}');
    expect(oe.canonicalize({ s: "\u0007\"\\/\u00e9" })).toBe('{"s":"\\u0007\\"\\\\/\u00e9"}');
    expect(oe.canonicalize({ a: undefined, b: 2 })).toBe('{"b":2}');
    expect(() => oe.canonicalize(undefined)).toThrow();
    expect(() => oe.canonicalize({ x: NaN })).toThrow();
  });
  it("sha256", async () => {
    expect(await oe.sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(hex(await oe.sha256(new Uint8Array()))).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });
  it("base58btc round trips and keeps leading zeros", () => {
    expect(oe.base58btcEncode(new TextEncoder().encode("Hello World!"))).toBe("2NEpo7TZRRrLZSi2U");
    expect(oe.base58btcEncode(Uint8Array.of(0, 0, 1))).toBe("112");
    expect(oe.base58btcEncode(new Uint8Array())).toBe("");
    for (const b of [Uint8Array.of(0), Uint8Array.of(0, 0, 255, 3), crypto.getRandomValues(new Uint8Array(34))])
      expect(oe.base58btcDecode(oe.base58btcEncode(b))).toEqual(b);
    expect(() => oe.base58btcDecode("0OIl")).toThrow();
  });
  it("randomNonce and nowSeconds", () => {
    const n = oe.randomNonce();
    expect(oe.base58btcDecode(n).length).toBe(16);
    expect(n).not.toBe(oe.randomNonce());
    expect(oe.nowSeconds()).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  });
});

describe("keys and DIDs", () => {
  it("did:key from a seed starts with z6Mk and round trips", async () => {
    const kp = await oe.keyPairFromSeed(seed);
    expect(kp.did).toMatch(/^did:key:z6Mk/);
    expect(oe.publicKeyFromDidKey(kp.did)).toEqual(kp.publicKey);
    expect(oe.verificationMethodId(kp.did)).toBe(`${kp.did}#${kp.did.slice(8)}`);
    expect(kp.publicJwk).toEqual({ kty: "OKP", crv: "Ed25519", x: kp.privateJwk.x });
  });
  it("matches the did:key spec example key (did:key test vector)", () => {
    // W3C did:key spec Ed25519 example
    const did = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";
    expect(oe.didKeyFromPublicKey(oe.publicKeyFromDidKey(did))).toBe(did);
  });
  it("generate and reload from JWK", async () => {
    const kp = await oe.generateKeyPair();
    const again = await oe.keyPairFromJwk(kp.privateJwk);
    expect(again.did).toBe(kp.did);
    await expect(oe.keyPairFromJwk({ ...kp.privateJwk, x: (await oe.generateKeyPair()).publicJwk.x })).rejects.toThrow();
  });
  it("rejects non-Ed25519 did:key", () => {
    // secp256k1 did:key (multicodec 0xe7)
    expect(() => oe.publicKeyFromDidKey("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme")).toThrow();
    expect(() => oe.publicKeyFromDidKey("did:web:example.com")).toThrow();
  });
  it("normalizeEid maps the legacy form", () => {
    expect(oe.normalizeEid("eid:base:0xabc")).toBe("did:pkh:eip155:8453:0xabc");
    expect(oe.normalizeEid("did:key:z6Mk1")).toBe("did:key:z6Mk1");
  });
});

describe("proofs", () => {
  it("sign and verify, tamper fails", async () => {
    const kp = await oe.keyPairFromSeed(seed);
    const signed = await oe.signObject({ spec: oe.SPEC, type: "Test", n: 1 }, kp, "2026-10-24T19:00:00Z");
    expect(signed.proof.proofValue.startsWith("z")).toBe(true);
    expect(await oe.verifyObject(signed)).toEqual({ ok: true, signer: kp.did });
    expect((await oe.verifyObject({ ...signed, n: 2 } as typeof signed)).ok).toBe(false);
    expect((await oe.verifyObject({ ...signed, proof: { ...signed.proof, created: "2026-10-24T19:00:01Z" } })).ok).toBe(false);
    const other = await oe.generateKeyPair();
    const vm = oe.verificationMethodId(other.did);
    expect((await oe.verifyObject({ ...signed, proof: { ...signed.proof, verificationMethod: vm } })).ok).toBe(false);
    expect((await oe.verifyObject({ ...signed, proof: { ...signed.proof, cryptosuite: "eddsa-rdfc-2022" } })).ok).toBe(false);
    expect((await oe.verifyObject({ ...signed, proof: { ...signed.proof, proofPurpose: "authentication" } })).ok).toBe(false);
    expect((await oe.verifyObject({ n: 1 } as never)).ok).toBe(false);
  });
  it("detached proofs for ContinuityLink ignore the proofs array", async () => {
    const a = await oe.keyPairFromSeed(seed);
    const b = await oe.generateKeyPair();
    const body = { type: "ContinuityLink", previous: a.did, successor: b.did };
    const link = { ...body, proofs: [await oe.signProof(body, a), await oe.signProof(body, b)] };
    for (const p of link.proofs) expect((await oe.verifyProof(link, p)).ok).toBe(true);
    expect((await oe.verifyProof({ ...link, successor: a.did }, link.proofs[1])).ok).toBe(false);
  });
  it("custom resolver is used and unknown methods fail without one", async () => {
    const kp = await oe.keyPairFromSeed(seed);
    const signed = await oe.signObject({ x: 1 }, kp);
    expect((await oe.verifyObject(signed, async () => ({ ed25519: [] }))).ok).toBe(false);
    const web = { ...signed, proof: { ...signed.proof, verificationMethod: "did:web:example.com#k" } };
    expect((await oe.verifyObject(web)).error).toMatch(/resolver/);
    expect(await oe.verifyObject(signed, async () => ({ ed25519: [(await oe.generateKeyPair()).publicKey, kp.publicKey] }))).toEqual({ ok: true, signer: kp.did });
  });
  it("EIP-712 digest matches viem and recovers a fixed throwaway key", async () => {
    // PUBLISHED THROWAWAY secp256k1 key for tests only.
    const account = privateKeyToAccount(`0x${"11".repeat(32)}`);
    const obj = { spec: oe.SPEC, type: "Declaration", eid: `did:pkh:eip155:8453:${account.address}` };
    const canonicalHash = await oe.sha256Hex(oe.canonicalize(obj));
    const created = "2026-10-24T19:00:00Z";
    const typed = {
      domain: { name: "Open Entity", version: "1" },
      types: { OpenEntityObject: [{ name: "objectType", type: "string" }, { name: "canonicalHash", type: "bytes32" }, { name: "created", type: "string" }] },
      primaryType: "OpenEntityObject",
      message: { objectType: "Declaration", canonicalHash: `0x${canonicalHash}`, created },
    } as const;
    const digest = oe.eip712Digest("Declaration", canonicalHash, created);
    expect(`0x${hex(digest)}`).toBe(hashTypedData(typed));
    const sig = await account.signTypedData(typed);
    expect(oe.recoverEip712(digest, sig)).toBe(account.address);
    expect(await recoverTypedDataAddress({ ...typed, signature: sig })).toBe(account.address);
    const proof = { type: "EthereumEip712Signature2021", created, verificationMethod: `${obj.eid}#blockchainAccountId`, proofPurpose: "assertionMethod", proofValue: sig };
    expect(await oe.verifyProof(obj, proof)).toEqual({ ok: true, signer: obj.eid });
    expect((await oe.verifyProof({ ...obj, eid: "x" }, proof)).ok).toBe(false);
    expect(() => oe.recoverEip712(digest, "0x1234")).toThrow();
  });
  it("recovers the well-known address of private key 1", async () => {
    const account = privateKeyToAccount(`0x${"00".repeat(31)}01`);
    expect(account.address).toBe("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
    const digest = oe.eip712Digest("EntityDocument", "00".repeat(32), "2026-10-24T19:00:00Z");
    const sig = await account.sign({ hash: `0x${hex(digest)}` });
    expect(oe.recoverEip712(digest, sig)).toBe("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
  });
});

describe("declaration", () => {
  it("text equals spec/declaration-1.0.txt and its hash", async () => {
    expect(oe.DECLARATION_TEXT).toBe(read("spec/declaration-1.0.txt").toString("utf8"));
    expect(await oe.sha256Hex(read("spec/declaration-1.0.txt"))).toBe(oe.DECLARATION_SHA256);
    expect(read("spec/declaration-1.0.sha256").toString().trim()).toBe(oe.DECLARATION_SHA256);
    expect(await oe.sha256Hex(oe.DECLARATION_TEXT)).toBe(oe.DECLARATION_SHA256);
  });
  it("text matches the code block in spec 6.1", () => {
    const spec = read("spec/OEIS-1.md").toString();
    const block = spec.split("### 6.1")[1].split("```\n")[1];
    expect(oe.DECLARATION_TEXT).toBe(block);
  });
  it("buildDeclaration carries the text hash and a fresh nonce", () => {
    const d = oe.buildDeclaration({ eid: "did:key:z6Mk1", name: "N" }) as Record<string, string>;
    expect(d.text_sha256).toBe(oe.DECLARATION_SHA256);
    expect(d.type).toBe("Declaration");
    expect(oe.base58btcDecode(d.nonce).length).toBe(16);
  });
});

describe("objects and validation", () => {
  it("buildDocument defaults validate once signed", async () => {
    const kp = await oe.keyPairFromSeed(seed);
    const doc = await oe.signObject(oe.buildDocument({ kp, name: "N", description: "D", extra: { endpoints: { web: "https://x" } } }), kp);
    expect(oe.validate("EntityDocument", doc)).toEqual({ ok: true, errors: [] });
    expect((doc as Record<string, unknown>).seq).toBe(1);
    expect(oe.validate("EntityDocument", { ...doc, name: "x".repeat(81) }).ok).toBe(false);
    expect(oe.validate("EntityDocument", { ...doc, created: "2026-10-24 19:00:00" }).ok).toBe(false);
    const { proof: _p, ...unsigned } = doc;
    expect(oe.validate("EntityDocument", unsigned).ok).toBe(false);
    const big = { ...doc, extensions: { "x:pad": "a".repeat(70_000) } };
    expect(oe.validate("EntityDocument", big).errors[0]).toMatch(/max 65536/);
  });
  it("record entries: chain rule in schema, 16 KB cap, stance payload", async () => {
    const v = JSON.parse(read("test-vectors/record-2.json").toString()).object;
    expect(oe.validate("RecordEntry", v).ok).toBe(true);
    expect(oe.validate("RecordEntry", { ...v, seq: 1 }).ok).toBe(false); // seq 1 needs prev null
    expect(oe.validate("RecordEntry", { ...v, prev: null }).ok).toBe(false);
    expect(oe.validate("RecordEntry", { ...v, payload: { ...v.payload, context: "c".repeat(501) } }).ok).toBe(false);
    expect(oe.validate("RecordEntry", { ...v, kind: "custom:acme:thing", payload: { pad: "p".repeat(17_000) } }).errors[0]).toMatch(/max 16384/);
    expect(oe.validate("RecordEntry", { ...v, kind: "custom:acme:thing", payload: {} }).ok).toBe(true);
    expect(oe.validate("RecordEntry", { ...v, kind: "made_up" }).ok).toBe(false);
  });
  it("every vector validates against its schema; malformed objects do not", () => {
    const types: Record<string, Parameters<typeof oe.validate>[0]> = {
      declaration: "Declaration",
      "entity-document": "EntityDocument",
      "record-1": "RecordEntry",
      "record-2": "RecordEntry",
      attestation: "Attestation",
      "continuity-link": "ContinuityLink",
      "log-leaf-0": "LogLeaf",
    };
    for (const [name, type] of Object.entries(types)) {
      const o = JSON.parse(read(`test-vectors/${name}.json`).toString()).object;
      expect(oe.validate(type, o), name).toEqual({ ok: true, errors: [] });
      expect(oe.validate(type, { ...o, spec: "openentity/0.9", type: "Nope", eid: 5 }).ok, name).toBe(false);
    }
    expect(oe.validate("LogLeaf", { type: "Declaration", eid: "did:key:z6Mk1", object_sha256: "0".repeat(64), received_at: "2026-10-24T19:00:00Z", email: "a@b" }).ok).toBe(false);
    expect(oe.validate("Attestation", { nope: 1 }).ok).toBe(false);
    expect(oe.validate("Nope" as never, {}).ok).toBe(false);
    expect(oe.validate("Declaration", { x: 1n }).ok).toBe(false);
  });
  it("Withdrawal, Revocation and Dispute schemas", async () => {
    const kp = await oe.keyPairFromSeed(seed);
    const base = { spec: oe.SPEC, created: "2026-10-24T19:00:00Z" };
    const w = await oe.signObject({ ...base, type: "Withdrawal", eid: kp.did, declaration_version: "1.0", name: "N", nonce: oe.randomNonce() }, kp);
    const r = await oe.signObject({ ...base, type: "Revocation", issuer: kp.did, attestation_sha256: "a".repeat(64) }, kp);
    const d = await oe.signObject({ ...base, type: "Dispute", issuer: kp.did, subject: kp.did, reason: "impersonation", statement: "s", nonce: oe.randomNonce() }, kp);
    expect(oe.validate("Withdrawal", w).ok).toBe(true);
    expect(oe.validate("Revocation", r).ok).toBe(true);
    expect(oe.validate("Dispute", d).ok).toBe(true);
    expect(oe.validate("Revocation", { ...r, attestation_sha256: "xyz" }).ok).toBe(false);
  });
  it("recordEntryHash includes the proof", async () => {
    const r1 = JSON.parse(read("test-vectors/record-1.json").toString());
    const r2 = JSON.parse(read("test-vectors/record-2.json").toString()).object;
    expect(await oe.recordEntryHash(r1.object)).toBe(r1.sha256);
    expect(r2.prev).toBe(r1.sha256);
    const { proof: _p, ...noProof } = r1.object;
    expect(await oe.recordEntryHash(noProof)).not.toBe(r2.prev);
  });
  it("checkTimestamp enforces spec 4.4", () => {
    expect(oe.checkTimestamp("2026-10-24T19:00:00Z", NOW)).toBeNull();
    expect(oe.checkTimestamp("2026-10-24T19:09:59Z", NOW)).toBeNull();
    expect(oe.checkTimestamp("2026-10-24T19:10:01Z", NOW)).toMatch(/future/);
    expect(oe.checkTimestamp("2026-10-23T19:00:00Z", NOW)).toBeNull();
    expect(oe.checkTimestamp("2026-10-23T18:59:59Z", NOW)).toMatch(/past/);
    expect(oe.checkTimestamp("2026-10-24T19:00:00.000Z", NOW)).toMatch(/RFC 3339/);
    expect(oe.checkTimestamp("2026-02-30T19:00:00Z", NOW)).toMatch(/RFC 3339/);
    expect(oe.checkTimestamp("2026-10-24T19:00:00+00:00", NOW)).toMatch(/RFC 3339/);
  });
});

describe("proof-of-work stamp", () => {
  const eid = "did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7";
  it("mints and accepts", async () => {
    const h = await oe.mintStamp(8, eid, "2026-10-24T19:00:00Z");
    expect(h).toMatch(/^1:(\d+):(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z):(did:[^\s]+):([1-9A-HJ-NP-Za-km-z]+)$/);
    expect((await oe.sha256(h))[0]).toBe(0);
    expect(await oe.checkStamp(h, 8, eid, NOW)).toBeNull();
  });
  it("two stamps for the same eid and second differ, so registries can reject reuse", async () => {
    const a = await oe.mintStamp(8, eid, "2026-10-24T19:00:00Z");
    const b = await oe.mintStamp(8, eid, "2026-10-24T19:00:00Z");
    expect(a).not.toBe(b);
  });
  it("rejects wrong eid, stale, future, too few bits, malformed", async () => {
    const h = await oe.mintStamp(8, eid, "2026-10-24T19:00:00Z");
    expect(await oe.checkStamp(h, 8, "did:key:z6MkOther", NOW)).toMatch(/different eid/);
    expect(await oe.checkStamp(h, 8, eid, new Date("2026-10-24T19:10:01Z"))).toMatch(/older/);
    expect(await oe.checkStamp(h, 8, eid, new Date("2026-10-24T18:49:59Z"))).toMatch(/future/);
    expect(await oe.checkStamp(h, 9, eid, NOW)).toMatch(/9/);
    expect(await oe.checkStamp(h.replace(/^1:8:/, "1:30:"), 8, eid, NOW)).toMatch(/fewer than 8/);
    expect(await oe.checkStamp("garbage", 8, eid, NOW)).toMatch(/malformed/);
    expect(await oe.checkStamp(h.replace(/:([^:]+)$/, ":0OIl"), 8, eid, NOW)).toMatch(/malformed/);
  });
  it("finds a hash that misses the target for an unmined header", async () => {
    let unmined = "";
    for (let i = 0; ; i++) {
      unmined = `1:8:2026-10-24T19:00:00Z:${eid}:${oe.base58btcEncode(Uint8Array.of(1, i))}`;
      if ((await oe.sha256(unmined))[0] !== 0) break;
    }
    expect(await oe.checkStamp(unmined, 8, eid, NOW)).toMatch(/fewer than 8/);
  });
});

// Reference RFC 9162 section 2.1 written over index ranges, independent of the SDK's slicing code.
const H = (...p: Uint8Array[]) => new Uint8Array(createHash("sha256").update(Buffer.concat(p)).digest());
const k2 = (n: number) => 2 ** Math.floor(Math.log2(n - 1));
function refMth(l: Uint8Array[], lo: number, hi: number): Uint8Array {
  const n = hi - lo;
  if (n === 0) return H();
  if (n === 1) return l[lo];
  const k = k2(n);
  return H(Uint8Array.of(1), refMth(l, lo, lo + k), refMth(l, lo + k, hi));
}
function refPath(m: number, l: Uint8Array[], lo: number, hi: number): Uint8Array[] {
  const n = hi - lo;
  if (n === 1) return [];
  const k = k2(n);
  return m < k ? [...refPath(m, l, lo, lo + k), refMth(l, lo + k, hi)] : [...refPath(m - k, l, lo + k, hi), refMth(l, lo, lo + k)];
}
function refSub(m: number, l: Uint8Array[], lo: number, hi: number, b: boolean): Uint8Array[] {
  const n = hi - lo;
  if (m === n) return b ? [] : [refMth(l, lo, hi)];
  const k = k2(n);
  return m <= k ? [...refSub(m, l, lo, lo + k, b), refMth(l, lo + k, hi)] : [...refSub(m - k, l, lo + k, hi, false), refMth(l, lo, lo + k)];
}

describe("Merkle (RFC 6962 / 9162)", () => {
  it("matches the Certificate Transparency reference roots", async () => {
    const inputs = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"];
    const roots = [
      "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
      "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
      "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
      "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
      "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
      "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
      "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
      "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];
    const leaves = await Promise.all(inputs.map((h) => oe.leafHash(h ? unhex(h) : new Uint8Array())));
    for (let n = 1; n <= 8; n++) expect(hex(await oe.merkleRoot(leaves.slice(0, n)))).toBe(roots[n - 1]);
    expect(hex(await oe.merkleRoot([]))).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(hex(await oe.nodeHash(leaves[0], leaves[1]))).toBe(roots[1]);
  });
  it("inclusion and consistency proofs for every index and size 1..40", async () => {
    const all = await Promise.all(Array.from({ length: 40 }, (_, i) => oe.leafHash(Uint8Array.of(i))));
    const flip = (b: Uint8Array) => Uint8Array.from(b, (x, i) => (i === 0 ? x ^ 1 : x));
    for (let n = 1; n <= 40; n++) {
      const l = all.slice(0, n);
      const root = await oe.merkleRoot(l);
      expect(root).toEqual(refMth(l, 0, n));
      for (let i = 0; i < n; i++) {
        const p = await oe.inclusionProof(i, l);
        expect(p).toEqual(refPath(i, l, 0, n));
        expect(await oe.verifyInclusion(i, n, l[i], p, root)).toBe(true);
        expect(await oe.verifyInclusion(i, n, flip(l[i]), p, root)).toBe(false);
        expect(await oe.verifyInclusion(n, n, l[i], p, root)).toBe(false);
        if (p.length) expect(await oe.verifyInclusion(i, n, l[i], [flip(p[0]), ...p.slice(1)], root)).toBe(false);
        if (n > 1) expect(await oe.verifyInclusion((i + 1) % n, n, l[i], p, root)).toBe(false);
      }
      for (let m = 1; m <= n; m++) {
        const p = await oe.consistencyProof(m, l);
        expect(p).toEqual(refSub(m, l, 0, n, true));
        const rootM = refMth(l, 0, m);
        expect(await oe.verifyConsistency(m, n, rootM, root, p)).toBe(true);
        expect(await oe.verifyConsistency(m, n, flip(rootM), root, p)).toBe(false);
        if (m < n) expect(await oe.verifyConsistency(m, n, rootM, flip(root), p)).toBe(false);
        if (p.length) expect(await oe.verifyConsistency(m, n, rootM, root, [...p.slice(0, -1), flip(p[p.length - 1])])).toBe(false);
      }
    }
    await expect(oe.inclusionProof(3, all.slice(0, 3))).rejects.toThrow();
    await expect(oe.consistencyProof(0, all)).rejects.toThrow();
  });
  it("logLeaf has exactly the spec 10.3 fields", () => {
    expect(oe.logLeaf("Declaration", "did:key:z6Mk1", "a".repeat(64), "2026-10-24T19:00:00Z")).toEqual({
      type: "Declaration",
      eid: "did:key:z6Mk1",
      object_sha256: "a".repeat(64),
      received_at: "2026-10-24T19:00:00Z",
    });
  });
});

describe("signed note checkpoint", () => {
  it("round trips and detects tampering", async () => {
    const kp = await oe.keyPairFromSeed(seed);
    const body = oe.checkpointBody("openentity.org/log", 6, new Uint8Array(32).fill(7));
    expect(body).toBe("openentity.org/log\n6\nBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\n");
    const note = await oe.signNote(body, "openentity.org/log", kp);
    expect(note.startsWith(body + "\n\u2014 openentity.org/log ")).toBe(true);
    expect(await oe.verifyNote(note, "openentity.org/log", kp.publicKey)).toBe(true);
    expect(await oe.verifyNote(note.replace("\n6\n", "\n7\n"), "openentity.org/log", kp.publicKey)).toBe(false);
    expect(await oe.verifyNote(note, "other.org/log", kp.publicKey)).toBe(false);
    expect(await oe.verifyNote(note, "openentity.org/log", (await oe.generateKeyPair()).publicKey)).toBe(false);
    expect(await oe.verifyNote(body, "openentity.org/log", kp.publicKey)).toBe(false);
    await expect(oe.signNote("no newline", "k", kp)).rejects.toThrow();
  });
  it("vkey carries the C2SP key id", async () => {
    const kp = await oe.keyPairFromSeed(seed);
    const [name, id, ...rest] = oe.noteVkey("openentity.org/log", kp.publicKey).split("+");
    const key = rest.join("+");
    expect(name).toBe("openentity.org/log");
    const raw = Buffer.from(key, "base64");
    expect(raw[0]).toBe(1);
    expect(new Uint8Array(raw.subarray(1))).toEqual(kp.publicKey);
    const want = await oe.sha256(new Uint8Array([...new TextEncoder().encode("openentity.org/log\n"), 1, ...kp.publicKey]));
    expect(id).toBe(hex(want.slice(0, 4)));
  });
});

describe("test vectors", () => {
  it("committed files equal a fresh deterministic generation", async () => {
    const fresh = await buildVectors();
    const files = readdirSync(new URL("test-vectors/", root)).filter((f) => f.endsWith(".json"));
    expect(files.sort()).toEqual(Object.keys(fresh).map((k) => `${k}.json`).sort());
    for (const [name, v] of Object.entries(fresh)) expect(read(`test-vectors/${name}.json`).toString(), name).toBe(serialize(v));
  });
  it("every signed vector verifies, hashes match, checkpoint verifies", async () => {
    const keys = JSON.parse(read("test-vectors/keys.json").toString());
    expect((await oe.keyPairFromSeed(unhex(keys.entity.seed))).did).toBe(keys.entity.eid);
    for (const name of ["declaration", "entity-document", "record-1", "record-2", "attestation"]) {
      const v = JSON.parse(read(`test-vectors/${name}.json`).toString());
      expect(oe.canonicalize(v.object)).toBe(v.canonical);
      expect(await oe.sha256Hex(v.canonical)).toBe(v.sha256);
      expect((await oe.verifyObject(v.object)).ok, name).toBe(true);
    }
    const link = JSON.parse(read("test-vectors/continuity-link.json").toString()).object;
    const signers = await Promise.all(link.proofs.map((p: oe.Proof) => oe.verifyProof(link, p)));
    expect(signers.map((s) => s.signer)).toEqual([keys.entity.eid, keys.second.eid]);
    const cp = JSON.parse(read("test-vectors/checkpoint.json").toString());
    expect(await oe.verifyNote(cp.note, "openentity.org/log", unhex(keys.log.publicKeyHex))).toBe(true);
    for (let i = 0; i < cp.tree_size; i++) {
      const leaf = JSON.parse(read(`test-vectors/log-leaf-${i}.json`).toString());
      expect(hex(await oe.leafHash(new TextEncoder().encode(leaf.canonical)))).toBe(leaf.leaf_hash);
      expect(await oe.verifyInclusion(i, cp.tree_size, unhex(leaf.leaf_hash), cp.inclusion_proofs[i].map(unhex), unhex(cp.root_hash))).toBe(true);
    }
  });
});

describe("custom claim types (spec/claim-types.md)", () => {
  const schema = (n: string) => JSON.parse(read(`spec/schemas/claims/${n}.json`).toString());
  const vector = (n: string) => JSON.parse(read(`test-vectors/${n}.json`).toString()).object;
  const cases: [string, string, string, object[]][] = [
    ["claim-liveness", "moltbotden-liveness", "custom:moltbotden:liveness",
      [{ method: "cron" }, { lease_until: "tomorrow" }, { observed_at: 5 }]],
    ["claim-endpoint-reliability", "clawgrc-endpoint_reliability", "custom:clawgrc:endpoint_reliability",
      [{ violation_rate: 1.2 }, { window: ["2026-10-17T00:00:00Z"] }, { host: "https://api.example.com/x" }, { reports: -1 }]],
    ["claim-vision-privacy", "securemyagent-vision_privacy", "custom:securemyagent:vision_privacy",
      [{ mode: "remote" }, { model_endpoint_class: "confidential_vm" }, { redaction: ["faces", "faces"] }, { redaction: ["voices"] }]],
  ];
  for (const [vec, sch, claimType, bad] of cases)
    it(`${claimType}: the signed vector verifies and fits its schema; broken variants do not`, async () => {
      const v = vector(vec), validator = new Validator(schema(sch), "2020-12", false);
      expect(v.claim_type).toBe(claimType);
      expect((await oe.verifyObject(v)).ok).toBe(true);
      expect(oe.validate("Attestation", v).ok).toBe(true);
      expect(validator.validate(v.claim).valid).toBe(true);
      for (const change of bad) expect(validator.validate({ ...v.claim, ...change }).valid, JSON.stringify(change)).toBe(false);
      expect(validator.validate({ ...v.claim, extra_field: 1 }).valid).toBe(true); // minor versions may add fields
      const { [Object.keys(v.claim)[0]]: _gone, ...missing } = v.claim;
      expect(validator.validate(missing).valid).toBe(false);
    });
  it("local mode needs a localhost endpoint, and confidential needs a confidential VM", () => {
    const validator = new Validator(schema("securemyagent-vision_privacy"), "2020-12", false);
    expect(validator.validate({ mode: "confidential", model_endpoint_class: "confidential_vm", redaction: [] }).valid).toBe(true);
    expect(validator.validate({ mode: "confidential", model_endpoint_class: "localhost", redaction: [] }).valid).toBe(false);
  });
});

describe("presentation (spec 4.7)", () => {
  const audience = "https://moltbotden.com";
  async function attestation(issuer: oe.KeyPair, subject: string, expires: string) {
    return oe.signObject({ spec: oe.SPEC, type: "Attestation", issuer: issuer.did, subject, claim_type: "trust_tier", claim: { tier: 2, platform: "moltbotden" }, created: oe.nowSeconds(), expires }, issuer);
  }

  it("proves control of the EID to one audience for one nonce, and checks carried attestations offline", async () => {
    const kp = await oe.generateKeyPair(), issuer = await oe.generateKeyPair(), nonce = oe.randomNonce();
    const good = await attestation(issuer, kp.did, "2099-01-01T00:00:00Z");
    const stale = await attestation(issuer, kp.did, "2020-01-01T00:00:00Z");
    const p = await oe.buildPresentation(kp, { audience, nonce, attestations: [good, stale] });
    const r = await oe.verifyPresentation(p, { audience, nonce });
    expect(r.ok).toBe(true);
    expect(r.attestations.map((a) => a.ok)).toEqual([true, false]);
    expect(r.attestations[1].error).toMatch(/expired/);

    expect((await oe.verifyPresentation(p, { audience: "https://evil.example", nonce })).errors.join()).toMatch(/audience/);
    expect((await oe.verifyPresentation(p, { audience, nonce: oe.randomNonce() })).errors.join()).toMatch(/nonce/);
    const late = new Date(Date.now() + 10 * 60_000);
    expect((await oe.verifyPresentation(p, { audience, nonce, now: late })).errors.join()).toMatch(/fresh/);
    // Signed by another key: not a proof of control.
    const other = await oe.generateKeyPair();
    const { proof: _p, ...body } = p as any;
    expect((await oe.verifyPresentation(await oe.signObject(body, other), { audience, nonce })).ok).toBe(false);
    // An attestation about someone else does not count for this entity.
    const elsewhere = await oe.buildPresentation(kp, { audience, nonce, attestations: [await attestation(issuer, other.did, "2099-01-01T00:00:00Z")] });
    expect((await oe.verifyPresentation(elsewhere, { audience, nonce })).attestations[0].error).toMatch(/subject/);
  });
});

describe("A2A Agent Card", () => {
  const doc = { eid: "did:key:z6MkX", name: "Ada", description: "Reviews code.", capabilities: ["code-review", "defi:smart-contracts"] };
  const docUrl = "https://openentity.org/v1/entities/did:key:z6MkX/document";
  it("carries the EID as a non-required AgentExtension (spec 11.2)", () => {
    expect(oe.a2aExtension(doc.eid, docUrl)).toMatchObject({ uri: "https://openentity.org/spec/1.0", required: false, params: { eid: doc.eid, document: docUrl } });
  });
  it("maps capabilities to skills and embeds the extension", () => {
    const c = oe.agentCard(doc, { url: "https://ada.example/a2a", documentUrl: docUrl });
    expect(c).toMatchObject({ name: "Ada", description: "Reviews code.", url: "https://ada.example/a2a", defaultInputModes: ["text/plain"], defaultOutputModes: ["text/plain"] });
    expect(c.skills).toEqual([
      { id: "code-review", name: "code review", description: "Self-declared capability: code-review", tags: ["code-review"] },
      { id: "defi:smart-contracts", name: "smart contracts", description: "Self-declared capability: defi:smart-contracts", tags: ["defi", "smart-contracts"] },
    ]);
    expect(c.capabilities.extensions).toEqual([oe.a2aExtension(doc.eid, docUrl)]);
    expect(oe.agentCard({ ...doc, capabilities: undefined }, { url: "u", documentUrl: docUrl }).skills).toEqual([]);
  });
});

describe("rotation", () => {
  const vec = () => JSON.parse(read("test-vectors/rotation.json").toString()).request;
  it("the rotation vector: both link proofs and the successor document verify, and both validate", async () => {
    const keys = JSON.parse(read("test-vectors/keys.json").toString());
    const { link, document } = vec();
    expect(oe.validate("ContinuityLink", link)).toEqual({ ok: true, errors: [] });
    expect(oe.validate("EntityDocument", document)).toEqual({ ok: true, errors: [] });
    expect((await Promise.all(link.proofs.map((p: oe.Proof) => oe.verifyProof(link, p)))).map((r) => r.signer)).toEqual([keys.entity.eid, keys.second.eid]);
    expect((await oe.verifyObject(document)).signer).toBe(keys.second.eid);
    expect(document).toMatchObject({ eid: keys.second.eid, seq: 1, continuity: { previous: keys.entity.eid } });
    expect(document.aliases).toBeUndefined();
  });
  it("a link whose body was altered fails its proofs", async () => {
    const { link } = vec();
    expect((await oe.verifyProof({ ...link, basis: "migration" }, link.proofs[0])).ok).toBe(false);
  });
  it("rotate() stamps for the successor, posts link and document, and returns the new key", async () => {
    const prev = await oe.generateKeyPair();
    const doc = await oe.signObject(oe.buildDocument({ kp: prev, name: "Old", description: "d" }), prev);
    const sent: { path: string; stamp?: string; body?: any }[] = [];
    const real = globalThis.fetch;
    globalThis.fetch = (async (url: string, init?: RequestInit) => {
      const path = new URL(url).pathname;
      sent.push({ path, stamp: (init?.headers as any)?.["x-oe-stamp"], body: init?.body && JSON.parse(init.body as string) });
      const reply = path.endsWith("/document") ? doc : path === "/v1/spec" ? { stamp_bits: 4 } : { ok: true };
      return new Response(JSON.stringify(reply), { status: 200 });
    }) as typeof fetch;
    try {
      const r = await oe.rotate({ previous: prev, registry: "https://r.example/" });
      const post = sent.find((s) => s.path === "/v1/continuity")!;
      expect(post.stamp).toContain(r.successor.did);
      expect(post.body.link.previous).toBe(prev.did);
      expect(post.body.link.successor).toBe(r.successor.did);
      expect((await Promise.all(post.body.link.proofs.map((p: oe.Proof) => oe.verifyProof(post.body.link, p)))).map((x) => x.signer)).toEqual([prev.did, r.successor.did]);
      expect((await oe.verifyObject(post.body.document)).signer).toBe(r.successor.did);
      // A refusal throws, so the caller never switches keys.
      globalThis.fetch = (async (url: string) => {
        const path = new URL(url).pathname;
        return new Response(JSON.stringify(path === "/v1/spec" ? { stamp_bits: 4 } : doc), { status: path === "/v1/continuity" ? 422 : 200 });
      }) as typeof fetch;
      await expect(oe.rotate({ previous: prev, registry: "https://r.example" })).rejects.toThrow(/422/);
    } finally {
      globalThis.fetch = real;
    }
  });
});
