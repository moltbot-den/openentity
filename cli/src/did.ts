import { base58btcDecode, publicKeyFromDidKey, normalizeEid, type Resolver } from "@openentity/sdk";
import { CliError, EXIT, usage } from "./errors";
import { fetchJson, type Obj } from "./http";

const keyDoc = (did: string): Obj => {
  const mb = did.slice("did:key:".length);
  publicKeyFromDidKey(did); // throws on non-Ed25519 did:key
  return { id: did, verificationMethod: [{ id: `${did}#${mb}`, type: "Multikey", controller: did, publicKeyMultibase: mb }] };
};

/** Resolve a DID to its DID document. did:key and did:pkh are offline; webvh is best effort (log not verified). */
export async function resolveDid(input: string): Promise<Obj> {
  const did = normalizeEid(input);
  const p = did.split(":");
  switch (p[1]) {
    case "key":
      try {
        return keyDoc(did);
      } catch (e: any) {
        throw new CliError(EXIT.VERIFY, `cannot resolve ${did}: ${e.message}`);
      }
    case "pkh":
      if (p[2] !== "eip155" || !/^0x[0-9a-fA-F]{40}$/.test(p[4] ?? "")) throw new CliError(EXIT.VERIFY, `unsupported did:pkh ${did}`);
      return { id: did, chainId: Number(p[3]), address: p[4] };
    case "web": {
      const host = decodeURIComponent(p[2] ?? "");
      const path = p.slice(3).map(decodeURIComponent).join("/");
      return fetchJson(path ? `https://${host}/${path}/did.json` : `https://${host}/.well-known/did.json`);
    }
    case "plc":
      return fetchJson(`https://plc.directory/${did}`);
    case "webvh": {
      const host = decodeURIComponent(p[3] ?? "");
      const path = p.slice(4).map(decodeURIComponent).join("/");
      const res = await fetch(path ? `https://${host}/${path}/did.jsonl` : `https://${host}/.well-known/did.jsonl`, { signal: AbortSignal.timeout(30_000) }).catch((e) => {
        throw new CliError(EXIT.NETWORK, `network error resolving ${did}: ${e.message}`);
      });
      if (!res.ok) throw new CliError(EXIT.NETWORK, `did:webvh log fetch failed: ${res.status}`);
      const last = (await res.text()).trim().split("\n").at(-1);
      const entry = JSON.parse(last ?? "{}");
      return { ...(entry.state ?? entry), _note: "did:webvh best effort: log history and witnesses are not verified" };
    }
  }
  throw usage(`unsupported DID method: ${did}`);
}

const b64u = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));

/** Ed25519 public keys from a DID document's verification methods. */
export function ed25519Keys(doc: Obj): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (const vm of doc.verificationMethod ?? []) {
    if (vm.publicKeyMultibase?.startsWith("z")) {
      const b = base58btcDecode(vm.publicKeyMultibase.slice(1));
      if (b.length === 34 && b[0] === 0xed && b[1] === 0x01) out.push(b.slice(2));
      else if (b.length === 32) out.push(b);
    } else if (vm.publicKeyJwk?.crv === "Ed25519" && vm.publicKeyJwk.x) out.push(b64u(vm.publicKeyJwk.x));
  }
  return out;
}

/** SDK Resolver backed by resolveDid, so verify works for did:web, did:plc and did:webvh signers too. */
export const resolver: Resolver = async (did) => {
  const base = did.split("#")[0];
  const doc = await resolveDid(base);
  return doc.address ? { address: doc.address } : { ed25519: ed25519Keys(doc) };
};
