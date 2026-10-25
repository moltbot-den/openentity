import { describe, expect, it } from "vitest";
import { buildDeclaration, generateKeyPair, mintStamp, nowSeconds, signObject } from "../src/sdk.ts";
import { E, adopted, call, signed, stamp, write } from "./helpers.ts";

describe("adopt", () => {
  it("lists a new entity at L0 with a log index and receipt", async () => {
    const { kp, res } = await adopted("Ada");
    expect(res.eid).toBe(kp.did);
    expect(res.level).toBe("L0");
    expect(res.log_index).toBeTypeOf("number");
    expect(res.receipt.leaf).toMatchObject({ type: "Declaration", eid: kp.did });
    const e = await call("GET", `/entities/${kp.did}`);
    expect(e.status).toBe(200);
    expect(e.body).toMatchObject({ level: "L0", log_index: res.log_index, lineage: { previous: null, successor: null } });
    expect(e.body.document.name).toBe("Ada");
    expect(e.body.declaration.type).toBe("Declaration");
    expect(e.body.aliases).toEqual([]);
  });

  it("validates the schema before checking any signature", async () => {
    const kp = await generateKeyPair();
    const { document, declaration } = await signed(kp);
    const bad = { ...document, name: "x".repeat(200), proof: { ...document.proof, proofValue: "zBroken" } };
    const r = await write("POST", "/adopt", kp.did, { document: bad, declaration });
    expect(r.status).toBe(422);
    expect(r.body.error).toBe("schema_invalid");
    const sigOnly = await write("POST", "/adopt", kp.did, { document: { ...document, proof: { ...document.proof, proofValue: "z" + "1".repeat(80) } }, declaration });
    expect(sigOnly.body.error).toBe("signature_invalid");
  });

  it("rejects a Declaration whose text hash is wrong", async () => {
    const kp = await generateKeyPair();
    const { document } = await signed(kp);
    const declaration = await signObject({ ...buildDeclaration({ eid: kp.did, name: "x" }), text_sha256: "0".repeat(64) }, kp);
    const r = await write("POST", "/adopt", kp.did, { document, declaration });
    expect(r.status).toBe(422);
    expect(r.body.error).toBe("declaration_hash_mismatch");
  });

  it("rejects a second Declaration for the same EID and version", async () => {
    const { kp, document } = await adopted();
    const declaration = await signObject(buildDeclaration({ eid: kp.did, name: "again" }), kp);
    const r = await write("POST", "/adopt", kp.did, { document, declaration });
    expect(r.status).toBe(409);
    expect(r.body.error).toBe("declaration_exists");
  });

  it("rejects objects outside the timestamp window", async () => {
    const kp = await generateKeyPair();
    const { document } = await signed(kp);
    const old = new Date(Date.now() - 2 * 86400_000).toISOString().replace(/\.\d+Z$/, "Z");
    const declaration = await signObject(buildDeclaration({ eid: kp.did, name: "x", created: old }), kp);
    const r = await write("POST", "/adopt", kp.did, { document, declaration });
    expect(r.body.error).toBe("timestamp_invalid");
  });

  it("rejects an object signed by another key", async () => {
    const kp = await generateKeyPair(), other = await generateKeyPair();
    const { document } = await signed(kp);
    const declaration = await signObject(buildDeclaration({ eid: kp.did, name: "x" }), other);
    const r = await write("POST", "/adopt", kp.did, { document, declaration });
    expect(r.body.error).toBe("signature_invalid");
  });

  it("accepts the legacy eid:base form only as a did:pkh and stores the DID form", async () => {
    const r = await call("GET", "/resolve/eid:base:0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0");
    expect(r.body.did).toBe("did:pkh:eip155:8453:0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0");
  });

  it("custodial mode returns the key once and stores only an encrypted copy on request", async () => {
    const r = await write("POST", "/adopt", "did:web:openentity.org", { custodial: true, name: "Keeper", keep_copy: true });
    expect(r.status).toBe(201);
    expect(r.body.custodial.private_key_jwk.d).toBeTypeOf("string");
    const row = (await E.db.first("SELECT enc_key FROM custodial_keys WHERE eid = $1", [r.body.eid]))?.enc_key;
    expect(row).toBeTruthy();
    expect(row).not.toContain(r.body.custodial.private_key_jwk.d);
    const doc = await call("GET", `/entities/${r.body.eid}/document`);
    expect(doc.body.operator.custody).toBe("registry");
    const noCopy = await write("POST", "/adopt", "did:web:openentity.org", { custodial: true, name: "Light" });
    expect(await E.db.first("SELECT 1 FROM custodial_keys WHERE eid = $1", [noCopy.body.eid])).toBeNull();
  });

  it("withdraws: the EID stays listed and marked withdrawn", async () => {
    const { kp } = await adopted();
    const w = await signObject({ spec: "openentity/1.0", type: "Withdrawal", eid: kp.did, declaration_version: "1.0", name: "Test Entity", created: nowSeconds(), nonce: "3yZe7d4Pd1rG5V8JQb1z2A" }, kp);
    const r = await write("POST", "/withdraw", kp.did, w);
    expect(r.status).toBe(201);
    const e = await call("GET", `/entities/${kp.did}`);
    expect(e.body).toMatchObject({ withdrawn: true, level: null });
  });
});

describe("stamp (spec 10.4)", () => {
  it("is required, bound to the EID, needs enough bits and is single use", async () => {
    const kp = await generateKeyPair();
    const objs = await signed(kp);
    expect((await call("POST", "/adopt", objs)).body.error).toBe("stamp_required");
    const other = await generateKeyPair();
    expect((await call("POST", "/adopt", objs, { "x-oe-stamp": await mintStamp(8, other.did) })).body.error).toBe("stamp_invalid");
    let weak = "";
    for (let i = 0; ; i++) {
      weak = `1:8:${nowSeconds()}:${kp.did}:${"2" + i.toString(36).replace(/[0lIO]/g, "z")}`;
      const h = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(weak)));
      if (h[0] !== 0) break;
    }
    expect((await call("POST", "/adopt", objs, { "x-oe-stamp": weak })).body.error).toBe("stamp_invalid");
    const s = await stamp(kp.did);
    expect((await call("POST", "/adopt", objs, s)).status).toBe(201);
    expect((await call("POST", "/adopt", objs, s)).body.error).toBe("stamp_reused");
  });

  it("caps writes per IP per day", async () => {
    const e = { ...E, IP_DAILY_LIMIT: "1" }, ip = { "cloudfront-viewer-address": `203.0.113.${Math.floor(Math.random() * 250)}:443` };
    const a = await generateKeyPair(), b = await generateKeyPair();
    expect((await call("POST", "/adopt", await signed(a), { ...(await stamp(a.did)), ...ip }, e)).status).toBe(201);
    expect((await call("POST", "/adopt", await signed(b), { ...(await stamp(b.did)), ...ip }, e)).body.error).toBe("rate_limited");
  });

  it("caps writes per IP per minute, keyed by the CloudFront viewer address", async () => {
    const e = { ...E, WRITE_PER_MINUTE: "1" }, ip = { "cloudfront-viewer-address": "2001:db8::7:51234" };
    const errors: string[] = [];
    // Three writes: even if a minute boundary falls between two of them, two share a minute.
    for (let i = 0; i < 3; i++) {
      const kp = await generateKeyPair();
      errors.push((await call("POST", "/adopt", await signed(kp), { ...(await stamp(kp.did)), ...ip }, e)).body.error);
    }
    expect(errors).toContain("rate_limited");
    const other = await generateKeyPair();
    expect((await call("POST", "/adopt", await signed(other), { ...(await stamp(other.did)), "cloudfront-viewer-address": "198.51.100.9:443" }, e)).status).toBe(201);
  });
});
