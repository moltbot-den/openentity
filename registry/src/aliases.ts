// DID resolution and alias proofs (spec 3.2, 3.4, 3.5).
import dns from "node:dns/promises";
import { BlockList, isIP } from "node:net";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { base58btcDecode, publicKeyFromDidKey, type Resolver } from "./sdk.ts";
import { type Env, hex, unhex } from "./env.ts";

const enc = new TextEncoder();
export const DOMAIN = /^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/;

const FETCH_TIMEOUT_MS = 5_000, FETCH_MAX_BYTES = 256 * 1024;

// Addresses a writer-chosen host name must never reach: loopback, private, link-local (cloud metadata, the Lambda runtime API),
// CGNAT, reserved and multicast. BlockList treats IPv4-mapped IPv6 as the IPv4 address.
const PRIVATE = new BlockList();
for (const [net, bits] of [["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["224.0.0.0", 3]] as const) PRIVATE.addSubnet(net, bits, "ipv4");
for (const [net, bits] of [["::", 128], ["::1", 128], ["64:ff9b::", 96], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8], ["2001:db8::", 32]] as const) PRIVATE.addSubnet(net, bits, "ipv6");

/** https only, no credentials, a DNS name (never an IP literal in any notation), and every address it resolves to is public. */
async function publicHttps(url: string): Promise<boolean> {
  let u: URL;
  try { u = new URL(url); } catch { return false; }
  if (u.protocol !== "https:" || u.username || u.password || isIP(u.hostname.replace(/^\[|\]$/g, "")) || !DOMAIN.test(u.hostname)) return false;
  // ponytail: resolved here, then fetch resolves again; a rebind between the two is the ceiling. Pin the address with a custom https agent if that matters.
  const addrs = await dns.lookup(u.hostname, { all: true }).catch(() => []);
  return addrs.length > 0 && addrs.every((a) => !PRIVATE.check(a.address, a.family === 6 ? "ipv6" : "ipv4"));
}

/** GET JSON from a host the caller does not control: public https hosts only, no redirects, 5 s overall, 256 KB at most. Null on any failure. */
export async function getJson(url: string): Promise<any> {
  if (!(await publicHttps(url))) return null;
  const res = await fetch(url, { headers: { accept: "application/json" }, redirect: "manual", signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!res.ok || !res.body) return null;
  const reader = res.body.getReader(), parts: Uint8Array[] = [];
  for (let n = 0; ; ) {
    const { done, value } = await reader.read();
    if (done) break;
    if ((n += value.length) > FETCH_MAX_BYTES) { await reader.cancel(); return null; }
    parts.push(value);
  }
  try { return JSON.parse(await new Blob(parts as BlobPart[]).text()); } catch { return null; }
}

/** DID document for did:key, did:pkh, did:web and did:plc; null when the method is unsupported or unreachable. */
export async function resolveDid(did: string): Promise<any> {
  if (did.startsWith("did:key:")) {
    publicKeyFromDidKey(did);
    const mb = did.slice(8), vm = `${did}#${mb}`;
    return { id: did, verificationMethod: [{ id: vm, type: "Multikey", controller: did, publicKeyMultibase: mb }], assertionMethod: [vm], authentication: [vm] };
  }
  const pkh = /^did:pkh:eip155:(\d+):(0x[0-9a-fA-F]{40})$/.exec(did);
  if (pkh) {
    const vm = `${did}#blockchainAccountId`;
    return { id: did, verificationMethod: [{ id: vm, type: "EcdsaSecp256k1RecoveryMethod2020", controller: did, blockchainAccountId: `eip155:${pkh[1]}:${pkh[2]}` }], assertionMethod: [vm] };
  }
  if (did.startsWith("did:web:")) {
    const [host, ...rest] = did.slice(8).split(":").map(decodeURIComponent);
    if (!DOMAIN.test(host)) return null;
    return getJson(rest.length ? `https://${host}/${rest.join("/")}/did.json` : `https://${host}/.well-known/did.json`);
  }
  if (/^did:plc:[a-z2-7]{24}$/.test(did)) return getJson(`https://plc.directory/${did}`);
  return null;
}

export const resolver: Resolver = async (did) => {
  const pkh = /^did:pkh:eip155:\d+:(0x[0-9a-fA-F]{40})$/.exec(did);
  if (pkh) return { address: pkh[1] };
  const doc = await resolveDid(did);
  const ed25519: Uint8Array[] = [];
  for (const vm of doc?.verificationMethod ?? []) {
    try {
      if (typeof vm.publicKeyMultibase === "string" && vm.publicKeyMultibase.startsWith("z6Mk")) ed25519.push(base58btcDecode(vm.publicKeyMultibase.slice(1)).slice(2));
      else if (vm.publicKeyJwk?.crv === "Ed25519") ed25519.push(Uint8Array.from(atob(vm.publicKeyJwk.x.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)));
    } catch { /* skip malformed keys */ }
  }
  return { ed25519 };
};

/** EIP-191 personal_sign recovery; returns the lowercase 0x address. */
export function personalRecover(message: string, sigHex: string): string {
  const msg = enc.encode(message);
  const digest = keccak_256(Uint8Array.from([...enc.encode(`\x19Ethereum Signed Message:\n${msg.length}`), ...msg]));
  const sig = unhex(sigHex.replace(/^0x/, ""));
  if (sig.length !== 65) throw new Error("signature must be 65 bytes");
  const v = sig[64] >= 27 ? sig[64] - 27 : sig[64];
  const pub = secp256k1.Signature.fromBytes(sig.slice(0, 64), "compact").addRecoveryBit(v).recoverPublicKey(digest).toBytes(false);
  return "0x" + hex(keccak_256(pub.slice(1)).slice(-20));
}
const personalDigest = (message: string) => {
  const msg = enc.encode(message);
  return keccak_256(Uint8Array.from([...enc.encode(`\x19Ethereum Signed Message:\n${msg.length}`), ...msg]));
};

async function ethCall(env: Env, to: string, data: string): Promise<string> {
  const res = await fetch(env.BASE_RPC_URL, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to, data }, "latest"] }),
  });
  const j: any = await res.json();
  if (j.error || typeof j.result !== "string") throw new Error(`eth_call failed: ${JSON.stringify(j.error)}`);
  return j.result;
}
const word = (n: bigint | number) => BigInt(n).toString(16).padStart(64, "0");
const selector = (sig: string) => hex(keccak_256(enc.encode(sig)).slice(0, 4));

/** ERC-1271 isValidSignature(bytes32,bytes) on Base. */
async function erc1271(env: Env, wallet: string, digest: Uint8Array, sigHex: string): Promise<boolean> {
  const sig = sigHex.replace(/^0x/, "");
  const data = "0x1626ba7e" + hex(digest) + word(64) + word(sig.length / 2) + sig.padEnd(Math.ceil(sig.length / 64) * 64, "0");
  return (await ethCall(env, wallet, data).catch(() => "0x")).startsWith("0x1626ba7e");
}

const SIWE = /^(\S+) wants you to sign in with your Ethereum account:\n(0x[0-9a-fA-F]{40})\n\n(.+)\n\nURI: (\S+)\nVersion: (\S+)\nChain ID: (\d+)\nNonce: (\S+)\nIssued At: (\S+)\nResources:\n- (\S+)$/;

/** Checks the fixed SIWE fields of spec 3.5 and returns the signing address (lowercase), or an error. */
async function checkSiwe(env: Env, eid: string, proof: any, chainId: string, address?: string): Promise<{ signer?: string; error?: string }> {
  if (proof?.type !== "Eip4361" || typeof proof.message !== "string" || typeof proof.signature !== "string") return { error: "proof must be {type: Eip4361, message, signature}" };
  const m = SIWE.exec(proof.message);
  if (!m) return { error: "message is not an EIP-4361 message with the fields of spec 3.5" };
  const [, domain, addr, statement, uri, version, chain, nonce, issued, resource] = m;
  if (domain !== env.REGISTRY_HOST) return { error: `domain must be ${env.REGISTRY_HOST}` };
  if (statement !== `Open Entity alias binding for ${eid}` || resource !== eid || uri !== `https://${env.REGISTRY_HOST}/v1/entities/${eid}`) return { error: "message is bound to a different EID" };
  if (version !== "1" || chain !== chainId || !/^[A-Za-z0-9]{8,}$/.test(nonce)) return { error: "version, chain id or nonce is wrong" };
  const t = Date.parse(issued), now = Date.now();
  if (Number.isNaN(t) || t > now + 10 * 60_000 || t < now - 24 * 3600_000) return { error: "issued-at must be within 24 hours of submission" };
  if (address && addr.toLowerCase() !== address.toLowerCase()) return { error: "message address does not match the alias" };
  let signer: string | undefined;
  try { signer = personalRecover(proof.message, proof.signature); } catch { /* maybe a contract wallet */ }
  if (signer === addr.toLowerCase()) return { signer };
  if (chainId === "8453" && (await erc1271(env, addr, personalDigest(proof.message), proof.signature))) return { signer: addr.toLowerCase() };
  return { error: "signature does not recover to the message address" };
}

/** The string an eth_call returned (ABI: offset, length, bytes); "" when malformed. */
function abiString(result: string): string {
  try {
    const h = result.slice(2), off = Number(BigInt("0x" + h.slice(0, 64))) * 2, len = Number(BigInt("0x" + h.slice(off, off + 64))) * 2;
    return len > 2 * FETCH_MAX_BYTES ? "" : new TextDecoder().decode(unhex(h.slice(off + 64, off + 64 + len)));
  } catch { return ""; }
}

/**
 * ERC-8004 second path (spec 3.4): the agent's registration file (its agentURI, read with tokenURI) lists a `DID`
 * service whose endpoint is the root EID. https (public host names only), ipfs (through a public gateway) and
 * on-chain data: URIs; the file is fetched with the same bounds as every other alias proof.
 */
async function registrationFile(env: Env, eid: string, registry: string, agentId: bigint): Promise<string | null> {
  const uri = abiString(await ethCall(env, registry, "0x" + selector("tokenURI(uint256)") + word(agentId)).catch(() => "0x"));
  let file: any = null;
  const data = /^data:application\/json(;base64)?,(.*)$/s.exec(uri);
  if (data) {
    try { file = JSON.parse(data[1] ? new TextDecoder().decode(Uint8Array.from(atob(data[2]), (c) => c.charCodeAt(0))) : decodeURIComponent(data[2])); } catch { /* not JSON */ }
  } else if (uri.startsWith("ipfs://")) file = await getJson(`https://ipfs.io/ipfs/${uri.slice(7)}`).catch(() => null);
  else if (uri.startsWith("https://")) file = await getJson(uri).catch(() => null);
  else return "the agent's agentURI must be https:// on a host name, ipfs:// or a data:application/json URI";
  // ERC-8004 drafts named the list `endpoints`; the final text names it `services`.
  const services = [...(Array.isArray(file?.services) ? file.services : []), ...(Array.isArray(file?.endpoints) ? file.endpoints : [])];
  return services.some((s: any) => s?.name === "DID" && s.endpoint === eid) ? null : "the agent's registration file lists no DID service naming this EID";
}

export const platformDomain =(value: string) => { const p = value.split(":")[0]; return p.includes(".") ? p : `${p}.com`; };

export interface AliasInput { type: string; value: string; proof?: any }

/** Verifies an alias proof against the root EID. Returns null when verified, else the reason. */
export async function verifyAlias(env: Env, eid: string, a: AliasInput): Promise<string | null> {
  if (a.type === "domain") {
    const m = /^did:web:([a-z0-9.-]+)$/.exec(a.value);
    if (!m || !DOMAIN.test(m[1])) return "domain alias value must be did:web:<domain>";
    const wk = await getJson(`https://${m[1]}/.well-known/openentity.json`).catch(() => null);
    if (wk?.eid === eid) return null;
    const dns = await getJson(`https://cloudflare-dns.com/dns-query?name=_openentity.${m[1]}&type=TXT`).catch(() => null);
    const txt = (dns?.Answer ?? []).map((r: any) => String(r.data).replace(/^"|"$/g, "").replace(/" "/g, ""));
    return txt.includes(`eid=${eid}`) ? null : "neither /.well-known/openentity.json nor _openentity TXT names this EID";
  }
  if (a.type === "wallet") {
    const m = /^did:pkh:eip155:(\d+):(0x[0-9a-fA-F]{40})$/.exec(a.value);
    if (!m) return "wallet alias value must be did:pkh:eip155:<chainId>:<address>";
    return (await checkSiwe(env, eid, a.proof, m[1], m[2])).error ?? null;
  }
  if (a.type === "erc8004") {
    const m = /^eip155:(\d+):(0x[0-9a-fA-F]{40}):(\d+)$/.exec(a.value);
    if (!m) return "erc8004 alias value must be eip155:<chainId>:<identityRegistry>:<agentId>";
    if (m[1] !== "8453") return "only Base (eip155:8453) ERC-8004 registries are supported";
    if (a.proof?.type !== "Eip4361") return registrationFile(env, eid, m[2], BigInt(m[3]));
    const r = await checkSiwe(env, eid, a.proof, m[1]);
    if (r.error) return r.error;
    const id = word(BigInt(m[3]));
    const addrOf = async (sig: string) => "0x" + (await ethCall(env, m[2], "0x" + selector(sig) + id).catch(() => "0x")).slice(-40).toLowerCase();
    if ((await addrOf("ownerOf(uint256)")) === r.signer || (await addrOf("getAgentWallet(uint256)")) === r.signer) return null;
    return "signing wallet is neither ownerOf nor getAgentWallet for this agent";
  }
  if (a.type === "platform") {
    const m = /^([a-z0-9.-]+):([A-Za-z0-9._-]{1,64})$/.exec(a.value);
    if (!m) return "platform alias value must be <platform>:<handle>";
    const p = a.proof;
    if (typeof p?.issued !== "string") return "proof must carry issued";
    const t = Date.parse(p.issued);
    if (Number.isNaN(t) || t > Date.now() + 10 * 60_000 || t < Date.now() - 24 * 3600_000) return "issued must be within 24 hours of submission";
    const text = `Open Entity alias binding\neid: ${eid}\nalias: ${a.value}\nissued: ${p.issued}`;
    // An Ed25519 root signs the spec 3.5 text directly; a did:pkh root signs it with its wallet (EIP-191, or ERC-1271 on Base).
    const pkh = /^did:pkh:eip155:(\d+):(0x[0-9a-fA-F]{40})$/.exec(eid);
    if (p.type === "Eip191BindingSignature" && pkh && typeof p.signature === "string") {
      let signer: string | undefined;
      try { signer = personalRecover(text, p.signature); } catch { /* maybe a contract wallet */ }
      const ok = signer === pkh[2].toLowerCase() || (pkh[1] === "8453" && (await erc1271(env, pkh[2], personalDigest(text), p.signature)));
      if (!ok) return "binding signature is not by this EID's wallet over the spec 3.5 text";
    } else if (p.type === "Ed25519BindingSignature" && typeof p.proofValue === "string") {
      let sig: Uint8Array<ArrayBuffer>;
      try { sig = new Uint8Array(base58btcDecode(p.proofValue.replace(/^z/, ""))); } catch { return "proofValue is not base58btc"; }
      let signed = false;
      for (const pk of (await resolver(eid)).ed25519 ?? []) {
        const key = await crypto.subtle.importKey("raw", new Uint8Array(pk), { name: "Ed25519" }, false, ["verify"]);
        // Accept the spec 3.5 block with or without a final newline.
        if ((await crypto.subtle.verify("Ed25519", key, sig, enc.encode(text))) || (await crypto.subtle.verify("Ed25519", key, sig, enc.encode(text + "\n")))) signed = true;
      }
      if (!signed) return "binding signature is not by this EID over the spec 3.5 text";
    } else return "proof must be {type: Ed25519BindingSignature, issued, proofValue} or, for a did:pkh root, {type: Eip191BindingSignature, issued, signature}";
    // The signature alone never binds: the platform must publish the binding too.
    // ponytail: a dotless platform name maps to <name>.com; add a platform registry when a platform needs another TLD.
    const domain = platformDomain(a.value);
    if (!DOMAIN.test(domain)) return "platform domain is not valid";
    const b = await getJson(`https://${domain}/.well-known/openentity/bindings/${m[2]}.json`).catch(() => null);
    return b?.eid === eid ? null : "platform binding does not name this EID";
  }
  return `alias type ${a.type} is not supported`;
}
