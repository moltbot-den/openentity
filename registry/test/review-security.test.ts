// Attacker-minded review findings (unauthenticated surface). Each test fails if its fix is removed.
import { afterEach, describe, expect, it, vi } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { canonicalize, eip712Digest, generateKeyPair, nowSeconds, randomNonce, sha256Hex, signProof, verifyObject } from "../src/sdk.ts";
import { hex, unhex } from "../src/env.ts";
import { adopted, call, didWebDoc, mockFetch, signAs, signed, write } from "./helpers.ts";

afterEach(() => vi.restoreAllMocks());

describe("recovery needs the key holder's consent to the alias", () => {
  it("an alias an outsider bound to the EID cannot take the entity over", async () => {
    const victim = await adopted("Victim");
    const evil = await generateKeyPair(), succ = await generateKeyPair();
    mockFetch({
      "evil.example/.well-known/openentity.json": () => ({ eid: victim.kp.did }), // anyone can publish a file naming any EID
      "evil.example/.well-known/did.json": () => didWebDoc("evil.example", evil),
    });
    expect((await write("POST", `/entities/${victim.kp.did}/aliases`, victim.kp.did, { type: "domain", value: "did:web:evil.example" })).status).toBe(201);
    const { document } = await signed(succ, "Takeover");
    const unsigned = { spec: "openentity/1.0", type: "ContinuityLink", previous: victim.kp.did, successor: succ.did, basis: "recovery", created: nowSeconds(), nonce: randomNonce() };
    const link = { ...unsigned, proofs: [await signProof(unsigned, succ), await signAs(unsigned, evil, "did:web:evil.example#k")] };
    const r = await write("POST", "/continuity", succ.did, { link, document });
    expect([r.status, r.body.error]).toEqual([422, "recovery_alias_required"]);
    expect((await call("GET", `/entities/${victim.kp.did}`)).body.lineage.successor).toBeNull();
  });
});

describe("EIP-712 signatures are not malleable", () => {
  it("rejects the high-s twin of a valid signature, so one object has one hash", async () => {
    const priv = secp256k1.utils.randomSecretKey();
    const address = "0x" + hex(keccak_256(secp256k1.getPublicKey(priv, false).slice(1)).slice(-20));
    const eid = `did:pkh:eip155:8453:${address}`;
    const obj = { spec: "openentity/1.0", type: "Attestation", issuer: eid, subject: "did:key:z6Mkx", claim_type: "x", claim: {}, created: nowSeconds() };
    const created = nowSeconds();
    const sig = secp256k1.Signature.fromBytes(secp256k1.sign(eip712Digest("Attestation", await sha256Hex(canonicalize(obj)), created), priv, { prehash: false, format: "recovered" }), "recovered");
    const proofFor = (s: Uint8Array, v: number) => ({ type: "EthereumEip712Signature2021", created, verificationMethod: `${eid}#blockchainAccountId`, proofPurpose: "assertionMethod", proofValue: "0x" + hex(s) + (27 + v).toString(16) });
    const resolver = async () => ({ address });
    const good = proofFor(sig.toBytes("compact"), sig.recovery!);
    expect((await verifyObject({ ...obj, proof: good }, resolver)).ok).toBe(true);
    const rs = sig.toBytes("compact");
    const high = unhex((secp256k1.Point.Fn.ORDER - sig.s).toString(16).padStart(64, "0"));
    const twin = proofFor(Uint8Array.from([...rs.slice(0, 32), ...high]), sig.recovery! ^ 1);
    expect((await verifyObject({ ...obj, proof: twin }, resolver)).ok).toBe(false);
  });
});

describe("outbound-fetching reads", () => {
  it("POST /verify with a prototype property as the type is a schema failure, not a 500", async () => {
    for (const type of ["constructor", "__proto__", "toString"]) {
      const r = await call("POST", "/verify", { type });
      expect([type, r.status]).toEqual([type, 200]);
      expect(r.body.schema.ok).toBe(false);
    }
  });

  it("GET /resolve and POST /verify answer 429 past a per-IP minute budget", async () => {
    let last = 0;
    for (let i = 0; i < 70; i++) last = (await call("GET", "/resolve/did:key:z6Mkx", undefined, { "cloudfront-viewer-address": "198.51.100.77:4000" })).status;
    expect(last).toBe(429);
    last = 0;
    for (let i = 0; i < 70; i++) last = (await call("POST", "/verify", { type: "x" }, { "cloudfront-viewer-address": "198.51.100.78:4000" })).status;
    expect(last).toBe(429);
  });
});
