// In-browser verifier for /entities/<eid>, bundled to /verify.js by prebuild. Progressive enhancement only:
// the button stays hidden without JavaScript, and the page text never depends on it.
import { base58btcDecode, canonicalize, leafHash, recordEntryHash, sha256Hex, verifyInclusion, verifyNote, verifyObject } from '@openentity/sdk';

const button = document.querySelector<HTMLButtonElement>('.oe-verify');
const report = document.querySelector<HTMLPreElement>('.oe-verify-report');
const data = JSON.parse(document.getElementById('oe-objects')?.textContent || '{}');

async function run(): Promise<string[]> {
  const lines: string[] = [];
  const check = async (label: string, obj: any) => {
    if (!obj) return lines.push(`${label}: not present`);
    const r = await verifyObject(obj);
    lines.push(`${label}: ${r.ok && r.signer === data.eid ? 'signature valid, signed by this EID' : `FAILED (${r.error ?? `signer ${r.signer}`})`}`);
  };
  await check('Entity Document', data.document);
  await check('Declaration', data.declaration);
  const first = data.record?.[0];
  let prev: string | null = first && first.seq > 1 ? first.prev : null;
  for (const e of data.record ?? []) {
    if (e.redacted) {
      lines.push(`Record ${e.seq}: redacted placeholder${e.prev === prev ? ', chain intact' : ', CHAIN BROKEN'}`);
      prev = e.hash;
      continue;
    }
    await check(`Record ${e.seq}`, e);
    if (e.prev !== prev) lines.push(`Record ${e.seq}: CHAIN BROKEN (prev does not match the entry before it)`);
    prev = await recordEntryHash(e);
  }
  await logChecks(lines);
  return lines;
}

const get = async (path: string) => {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return r.json();
};
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const unhex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (b) => parseInt(b, 16));
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/** Checkpoint signature against the registry log key, an inclusion proof per leaf bound to the object it covers, and attestation signatures. */
async function logChecks(lines: string[]) {
  const leaves: Array<[string, number, any]> = [];
  if (data.log?.declaration != null) leaves.push(['Declaration', data.log.declaration, data.declaration]);
  for (const a of data.log?.attestations ?? []) {
    const name = `Attestation ${String(a.attestation.claim_type)}`;
    const r = await verifyObject(a.attestation);
    lines.push(`${name}: ${r.ok && r.signer?.split('#')[0] === a.attestation.issuer ? 'signature valid, signed by its issuer' : `FAILED (${r.error ?? `signer ${r.signer}`})`}`);
    leaves.push([name, a.log_index, a.attestation]);
  }
  if (!leaves.length) return void lines.push('Log inclusion: no log index reported for this entity');
  let size = 0;
  let root = new Uint8Array();
  try {
    const [spec, sth] = await Promise.all([get('/v1/spec'), get('/v1/log/sth')]);
    const key = spec.registry?.publicKeyMultibase;
    const origin = spec.registry?.log_origin ?? 'openentity.org/log';
    if (!key || !(await verifyNote(sth.signature, origin, base58btcDecode(key.slice(1)).slice(-32)))) throw new Error('signature INVALID');
    // The signed body, not the JSON beside it, says which tree this is.
    const [o, n, rootB64] = sth.signature.split('\n');
    size = Number(n);
    root = unb64(rootB64);
    if (o !== origin || size !== sth.tree_size) throw new Error('signed body does not match the reported tree size');
    lines.push(`Checkpoint: signature valid, tree size ${size}`);
  } catch (e) {
    return void lines.push(`Checkpoint: FAILED (${(e as Error).message}); log inclusion not checked`);
  }
  for (const [label, i, obj] of leaves) {
    try {
      const [{ entries }, p] = await Promise.all([get(`/v1/log/entries?start=${i}&end=${i + 1}`), get(`/v1/log/proof/${i}?tree_size=${size}`)]);
      const leaf = entries?.[0]?.leaf;
      const lh = await leafHash(new TextEncoder().encode(canonicalize(leaf)));
      const bound = leaf?.object_sha256 === (await sha256Hex(canonicalize(obj)));
      const ok = bound && p.leaf_hash === hex(lh) && (await verifyInclusion(i, size, lh, p.proof.map(unhex), root));
      lines.push(`${label}: ${ok ? `log inclusion OK (leaf ${i} of ${size})` : `log inclusion FAILED (leaf ${i})`}`);
    } catch (e) {
      lines.push(`${label}: log inclusion FAILED (${(e as Error).message})`);
    }
  }
}

if (button && report) {
  button.hidden = false;
  button.addEventListener('click', async () => {
    report.hidden = false;
    report.textContent = 'Verifying...';
    try {
      report.textContent = (await run()).join('\n');
    } catch (e) {
      report.textContent = `Verification error: ${(e as Error).message}`;
    }
  });
}
