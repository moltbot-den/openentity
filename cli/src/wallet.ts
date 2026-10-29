import { readFile } from "node:fs/promises";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { usage } from "./errors";

const enc = new TextEncoder();
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const KEY = /^(0x)?[0-9a-fA-F]{64}$/;

/** EIP-55 checksum form of an address. */
export function checksum(addr: string): string {
  const a = addr.slice(2).toLowerCase();
  const h = hex(keccak_256(enc.encode(a)));
  return "0x" + [...a].map((c, i) => (parseInt(h[i], 16) >= 8 ? c.toUpperCase() : c)).join("");
}

export interface Signer {
  address: string;
  /** EIP-191 personal_sign, 0x-hex r || s || v. */
  sign(message: string): string;
}

function signerOf(keyHex: string): Signer {
  const priv = Uint8Array.from(Buffer.from(keyHex.replace(/^0x/, ""), "hex"));
  const address = checksum("0x" + hex(keccak_256(secp256k1.getPublicKey(priv, false).slice(1)).slice(-20)));
  return {
    address,
    sign(message) {
      const m = enc.encode(message);
      const digest = keccak_256(Uint8Array.from([...enc.encode(`\x19Ethereum Signed Message:\n${m.length}`), ...m]));
      const sig = secp256k1.Signature.fromBytes(secp256k1.sign(digest, priv, { prehash: false, format: "recovered" }), "recovered");
      return "0x" + hex(sig.toBytes("compact")) + (27 + sig.recovery!).toString(16);
    },
  };
}

/**
 * The wallet signer behind `--wallet` (PRD 7.2): a hex private key, or a file holding one. With no `--wallet`, the
 * OPENENTITY_WALLET_KEY environment variable. Returns null when `--wallet` is a bare address or did:pkh (declared, not proven).
 */
export async function resolveSigner(spec: string | undefined, env = process.env): Promise<Signer | null> {
  const s = spec ?? env.OPENENTITY_WALLET_KEY;
  if (!s) return null;
  if (KEY.test(s)) return signerOf(s);
  if (/^0x[0-9a-fA-F]{40}$/.test(s) || s.startsWith("did:pkh:")) return null;
  const text = (
    await readFile(s, "utf8").catch(() => {
      throw usage("--wallet is not a hex private key, a wallet address, a did:pkh or a readable key file");
    })
  ).trim();
  if (!KEY.test(text)) throw usage(`${s} does not hold a 32-byte hex private key`);
  return signerOf(text);
}
