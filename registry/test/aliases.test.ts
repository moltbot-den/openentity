import { afterEach, describe, expect, it, vi } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { base58btcEncode, buildDeclaration, buildDocument, canonicalize, eip712Digest, generateKeyPair, nowSeconds, sha256Hex, type KeyPair } from "../src/sdk.ts";
import { hex } from "../src/env.ts";
import { adopted, call, mockFetch, stamp, write } from "./helpers.ts";

afterEach(() => vi.restoreAllMocks());

const enc = new TextEncoder();
function wallet() {
  const priv = secp256k1.utils.randomSecretKey();
  const typed = async (obj: any) => {
    const created = nowSeconds();
    const d = eip712Digest(typeof obj.type === "string" ? obj.type : "EntityDocument", await sha256Hex(canonicalize(obj)), created);
    const sig = secp256k1.Signature.fromBytes(secp256k1.sign(d, priv, { prehash: false, format: "recovered" }), "recovered");
    return { type: "EthereumEip712Signature2021", created, proofPurpose: "assertionMethod", proofValue: "0x" + hex(sig.toBytes("compact")) + (27 + sig.recovery!).toString(16) };
  };
  const address = "0x" + hex(keccak_256(secp256k1.getPublicKey(priv, false).slice(1)).slice(-20));
  const sign = (msg: string) => {
    const m = enc.encode(msg);
    const digest = keccak_256(Uint8Array.from([...enc.encode(`\x19Ethereum Signed Message:\n${m.length}`), ...m]));
    const sig = secp256k1.Signature.fromBytes(secp256k1.sign(digest, priv, { prehash: false, format: "recovered" }), "recovered");
    return "0x" + hex(sig.toBytes("compact")) + (27 + sig.recovery!).toString(16);
  };
  return { address, sign, typed };
}
const siwe = (eid: string, address: string, chain = 8453) =>
  `openentity.org wants you to sign in with your Ethereum account:\n${address}\n\nOpen Entity alias binding for ${eid}\n\nURI: https://openentity.org/v1/entities/${eid}\nVersion: 1\nChain ID: ${chain}\nNonce: abcdEFGH1234\nIssued At: ${nowSeconds()}\nResources:\n- ${eid}`;

async function platformProof(kp: KeyPair, value: string) {
  const issued = nowSeconds();
  const text = `Open Entity alias binding\neid: ${kp.did}\nalias: ${value}\nissued: ${issued}`;
  const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", kp.privateKey, enc.encode(text)));
  return { type: "Ed25519BindingSignature", issued, proofValue: "z" + base58btcEncode(sig) };
}

/** Adopt a wallet-rooted entity (did:pkh) with EIP-712 proofs, as the Moltbot Den bridge does. */
async function pkhAdopted() {
  const w = wallet(), eid = `did:pkh:eip155:8453:${w.address}`, vm = `${eid}#blockchainAccountId`;
  const base: any = { ...buildDocument({ kp: await generateKeyPair(), name: "Wallet Wren", description: "A wallet-rooted entity." }), eid };
  base.keys = [{ id: vm, type: "Multikey", publicKeyMultibase: "zQ3s" + "1".repeat(44) }];
  delete base.proof;
  const decl: any = { ...buildDeclaration({ eid, name: "Wallet Wren" }) };
  delete decl.proof;
  const document = { ...base, proof: { ...(await w.typed(base)), verificationMethod: vm } };
  const declaration = { ...decl, proof: { ...(await w.typed(decl)), verificationMethod: vm } };
  const r = await call("POST", "/adopt", { document, declaration }, await stamp(eid));
  if (r.status !== 201) throw new Error(JSON.stringify(r.body));
  return { w, eid };
}

describe("aliases (spec 3.4, 3.5)", () => {
  it("platform: a did:pkh root binds with an EIP-191 signature over the spec 3.5 text", async () => {
    const { w, eid } = await pkhAdopted();
    const value = "den:wren";
    mockFetch({ "den.com/.well-known/openentity/bindings/wren.json": () => ({ eid }) });
    const issued = nowSeconds();
    const text = `Open Entity alias binding\neid: ${eid}\nalias: ${value}\nissued: ${issued}`;
    const other = wallet();
    expect((await write("POST", `/entities/${eid}/aliases`, eid, { type: "platform", value, proof: { type: "Eip191BindingSignature", issued, signature: other.sign(text) } })).body.error).toBe("alias_proof_invalid");
    const ok = await write("POST", `/entities/${eid}/aliases`, eid, { type: "platform", value, proof: { type: "Eip191BindingSignature", issued, signature: w.sign(text) } });
    expect(ok.status).toBe(201);
  });

  it("domain: binds when the well-known file names this EID, rejects another EID", async () => {
    const a = await adopted("A", { aliases: [{ type: "domain", value: "did:web:a.example" }] }), b = await adopted();
    mockFetch({ "a.example/.well-known/openentity.json": () => ({ eid: a.kp.did }) });
    const bad = await write("POST", `/entities/${b.kp.did}/aliases`, b.kp.did, { type: "domain", value: "did:web:a.example" });
    expect([bad.status, bad.body.error]).toEqual([422, "alias_proof_invalid"]);
    const ok = await write("POST", `/entities/${a.kp.did}/aliases`, a.kp.did, { type: "domain", value: "did:web:a.example" });
    expect(ok.status).toBe(201);
    expect(ok.body.level).toBe("L1");
  });

  it("domain: accepts the DNS TXT record", async () => {
    const a = await adopted();
    // Cloudflare's DoH endpoint answers only to `accept: application/dns-json`; with application/json it returns nothing.
    mockFetch({ "cloudflare-dns.com/dns-query?name=_openentity.txt.example": (req) => (req.headers.get("accept") === "application/dns-json" ? { Answer: [{ data: `"eid=${a.kp.did}"` }] } : new Response("", { status: 400 })) });
    expect((await write("POST", `/entities/${a.kp.did}/aliases`, a.kp.did, { type: "domain", value: "did:web:txt.example" })).status).toBe(201);
  });

  it("wallet: SIWE for this EID binds, the same signature replayed for another EID does not", async () => {
    const a = await adopted(), b = await adopted(), w = wallet();
    const message = siwe(a.kp.did, w.address);
    const proof = { type: "Eip4361", message, signature: w.sign(message) };
    const value = `did:pkh:eip155:8453:${w.address}`;
    const replay = await write("POST", `/entities/${b.kp.did}/aliases`, b.kp.did, { type: "wallet", value, proof });
    expect(replay.body.error).toBe("alias_proof_invalid");
    const forged = { ...proof, signature: wallet().sign(message) };
    mockFetch({ "rpc.test": () => ({ jsonrpc: "2.0", id: 1, result: "0x" }) });
    expect((await write("POST", `/entities/${a.kp.did}/aliases`, a.kp.did, { type: "wallet", value, proof: forged })).body.error).toBe("alias_proof_invalid");
    const ok = await write("POST", `/entities/${a.kp.did}/aliases`, a.kp.did, { type: "wallet", value, proof });
    expect(ok.status).toBe(201);
  });

  it("erc8004: binds only when the signing wallet is ownerOf or getAgentWallet", async () => {
    const a = await adopted(), w = wallet(), stranger = wallet();
    const message = siwe(a.kp.did, w.address);
    const proof = { type: "Eip4361", message, signature: w.sign(message) };
    const value = "eip155:8453:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432:42";
    let owner = stranger.address;
    mockFetch({ "rpc.test": () => ({ jsonrpc: "2.0", id: 1, result: "0x" + owner.slice(2).padStart(64, "0") }) });
    expect((await write("POST", `/entities/${a.kp.did}/aliases`, a.kp.did, { type: "erc8004", value, proof })).body.error).toBe("alias_proof_invalid");
    owner = w.address;
    expect((await write("POST", `/entities/${a.kp.did}/aliases`, a.kp.did, { type: "erc8004", value, proof })).status).toBe(201);
  });

  it("erc8004: binds through the agent's registration file when it lists a DID service naming the root EID (spec 3.4)", async () => {
    const a = await adopted(), b = await adopted();
    const value = "eip155:8453:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432:7";
    const abiString = (s: string) => {
      const h = hex(enc.encode(s));
      return "0x" + (32).toString(16).padStart(64, "0") + (h.length / 2).toString(16).padStart(64, "0") + h.padEnd(Math.ceil(h.length / 64) * 64, "0");
    };
    let uri = "https://agents.example/reg/7.json", file: any = {};
    const calls: string[] = [];
    mockFetch({
      "rpc.test": async (req) => {
        const data: string = (await req.json()).params[0].data;
        calls.push(data.slice(0, 10));
        return { jsonrpc: "2.0", id: 1, result: data.startsWith("0xc87b56dd") && data.endsWith("7".padStart(64, "0")) ? abiString(uri) : "0x" };
      },
      "agents.example/reg/7.json": () => file,
      "ipfs.io/ipfs/bafyfile": () => file,
    });
    const bind = () => write("POST", `/entities/${a.kp.did}/aliases`, a.kp.did, { type: "erc8004", value });
    const reg = (eid: string, key = "services") => ({ type: "https://eips.ethereum.org/EIPS/eip-8004#registration-v1", name: "Agent", [key]: [{ name: "A2A", endpoint: "https://agents.example/a2a" }, { name: "DID", endpoint: eid }] });

    file = reg(b.kp.did);
    expect((await bind()).body.error).toBe("alias_proof_invalid");
    file = { services: [{ name: "OpenEntity", endpoint: a.kp.did }] };
    expect((await bind()).body.error).toBe("alias_proof_invalid");
    uri = "https://169.254.169.254/latest/meta-data";
    file = reg(a.kp.did);
    expect((await bind()).body.error).toBe("alias_proof_invalid");
    uri = "ipfs://bafyfile";
    expect((await bind()).status).toBe(201);
    expect(calls).toContain("0xc87b56dd"); // tokenURI(uint256): ERC-8004's agentURI

    const c = await adopted();
    uri = `data:application/json;base64,${btoa(JSON.stringify(reg(c.kp.did, "endpoints")))}`;
    expect((await write("POST", `/entities/${c.kp.did}/aliases`, c.kp.did, { type: "erc8004", value })).status).toBe(201);
  });

  it("platform: needs both the entity's signature and the platform's binding file for this EID", async () => {
    const value = "den:eleanor";
    const a = await adopted("A", { aliases: [{ type: "platform", value }] }), b = await adopted();
    let named = b.kp.did;
    mockFetch({ "den.com/.well-known/openentity/bindings/eleanor.json": () => ({ eid: named }) });
    expect((await write("POST", `/entities/${a.kp.did}/aliases`, a.kp.did, { type: "platform", value, proof: await platformProof(a.kp, value) })).body.error).toBe("alias_proof_invalid");
    named = a.kp.did;
    expect((await write("POST", `/entities/${a.kp.did}/aliases`, a.kp.did, { type: "platform", value, proof: await platformProof(b.kp, value) })).body.error).toBe("alias_proof_invalid");
    const ok = await write("POST", `/entities/${a.kp.did}/aliases`, a.kp.did, { type: "platform", value, proof: await platformProof(a.kp, value) });
    expect(ok.status).toBe(201);
    expect((await call("GET", `/entities/${a.kp.did}`)).body.aliases[0]).toMatchObject({ type: "platform", value, status: "verified" });
  });
});
