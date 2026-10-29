import { describe, expect, it } from "vitest";
import * as oe from "../src/index.ts";
import * as node from "../src/node.ts";

// The public surface. Changing it on purpose means editing this list in the same PR; a stray export or a rename fails here.
const SNAPSHOT = [
  "A2A_EXTENSION_URI CLIENTS DECLARATION_SHA256 DECLARATION_TEXT DECLARATION_VERSION DEFAULT_REGISTRY DISPUTE_REASONS HttpSigError",
  "OpenEntityError SPEC a2aExtension adopt agentCard base58btcDecode base58btcEncode buildDeclaration buildDidDocument buildDocument",
  "buildOpenEntityJson buildPresentation buildRotation canonicalize checkStamp checkTimestamp checkpointBody clearTrustCache",
  "consistencyProof didKeyFromPublicKey didWebResolver dispute eip712Digest find generateKeyPair hashData httpSigBase inclusionProof",
  "keyPairFromJwk keyPairFromSeed leafHash logLeaf merkleRoot mintStamp nodeHash normalizeEid noteVkey nowSeconds parseJson present",
  "publicKeyFromDidKey randomNonce record recordEntryHash recoverEip712 rotate sha256 sha256Hex signAttestation signNote signObject",
  "signProof signRequest signRevocation successorDocument trust validate verificationMethodId verifyConsistency verifyInclusion",
  "verifyNote verifyObject verifyPresentation verifyProof verifyRequest withdraw",
].join(" ");

describe("public API", () => {
  it("exports exactly the documented names", () => {
    expect(Object.keys(oe).sort().join(" ")).toBe(SNAPSHOT);
  });
  it("@openentity/sdk/node exports", () => {
    expect(Object.keys(node).sort().join(" ")).toBe("Identity identityFile");
  });
});

describe("errors", () => {
  const stub = (status: number, body: unknown) => {
    globalThis.fetch = (async () => new Response(typeof body === "string" ? body : JSON.stringify(body), { status })) as typeof fetch;
  };
  it("a registry refusal carries the registry code and status", async () => {
    const real = globalThis.fetch;
    try {
      stub(409, { error: "entity_exists", message: "x" });
      const kp = await oe.generateKeyPair();
      const e = await oe.adopt(kp, { name: "n", registry: "https://r.example" }).catch((x) => x);
      expect(e).toBeInstanceOf(oe.OpenEntityError);
      expect(e).toBeInstanceOf(Error);
      expect([e.code, e.status]).toEqual(["entity_exists", 409]);
      stub(502, "<html>bad gateway</html>");
      expect((await oe.find({ registry: "https://r.example" }).catch((x) => x)).code).toBe("registry_error");
    } finally {
      globalThis.fetch = real;
    }
  });
  it("local failures are invalid_input; HttpSigError is an OpenEntityError", async () => {
    const kp = await oe.generateKeyPair();
    const e = await oe.dispute(kp, { subject: "did:key:z", reason: "nope" as never, statement: "s" }).catch((x) => x);
    expect(e).toBeInstanceOf(oe.OpenEntityError);
    expect(e.code).toBe("invalid_input");
    expect(new oe.HttpSigError("bad_signature")).toBeInstanceOf(oe.OpenEntityError);
  });
});

describe("registry client", () => {
  it("record() chains from the registry head and batches", async () => {
    const kp = await oe.generateKeyPair();
    const posts: any[] = [];
    const real = globalThis.fetch;
    globalThis.fetch = (async (url: string, init?: RequestInit) => {
      const p = new URL(url).pathname;
      if (init?.method === "POST") posts.push(JSON.parse(init.body as string));
      return new Response(JSON.stringify(p === "/v1/spec" ? { stamp_bits: 4 } : p.endsWith("/record") && !init?.method ? { head: { seq: 7, hash: "ab".repeat(32) } } : { ok: true }));
    }) as typeof fetch;
    try {
      const r = await oe.record(kp, [["stance", { a: 1 }], ["stance", { a: 2 }]], { registry: "https://r.example" });
      const [a, b] = posts[0].entries;
      expect([r.accepted, a.seq, a.prev, b.seq]).toEqual([2, 8, "ab".repeat(32), 9]);
      expect(b.prev).toBe(await oe.sha256Hex(oe.canonicalize(a)));
    } finally {
      globalThis.fetch = real;
    }
  });
});
