// The in-browser verify button: the page ships the button, the embedded objects and /verify.js, and the built script
// (public/verify.js, made by scripts/prebuild.mjs) reports a PASS for a real signed entity and FAILED for a tampered one.
// No DOM library: the script touches three elements, so a minimal stand-in for them is enough.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildDeclaration, buildDocument, canonicalize, checkpointBody, generateKeyPair, inclusionProof, leafHash, logLeaf, merkleRoot, nowSeconds, recordEntryHash, sha256Hex, signAttestation, signNote, signObject } from '@openentity/sdk';
import { renderEntity } from '../server/render';

const script = readFileSync(join(import.meta.dirname, '..', 'public', 'verify.js'), 'utf8');

async function entity() {
  const kp = await generateKeyPair();
  const document = await signObject(buildDocument({ kp, name: 'Verifier Fixture', description: 'Throwaway key, test only.' }), kp);
  const declaration = await signObject(buildDeclaration({ eid: kp.did, name: 'Verifier Fixture' }), kp);
  const e1 = await signObject({ spec: 'openentity/1.0', type: 'RecordEntry', eid: kp.did, seq: 1, prev: null, kind: 'stance', at: nowSeconds(), payload: { stance_type: 'refusal', reason_category: 'values', instruction_conflict: true, cost: 'low', context: 'Declined.' } }, kp);
  return { eid: kp.did, document, declaration, record: [e1] };
}

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

/** A two-leaf registry log (the Declaration and one Attestation) with a signed checkpoint, served through a fake fetch. */
async function logFixture(e: Awaited<ReturnType<typeof entity>>, tamper?: (r: Record<string, any>) => void, webIssuer?: string) {
  const reg = await generateKeyPair();
  const obs = await generateKeyPair();
  const att = await signAttestation(obs, { subject: e.eid, claimType: 'identity', claim: { name: 'Fixture', aliases_verified: [] }, ...(webIssuer && { issuer: `did:web:${webIssuer}`, keyId: 'k' }) } as any);
  const leaves = [
    logLeaf('Declaration', e.eid, await sha256Hex(canonicalize(e.declaration)), '2026-10-28T00:00:00Z'),
    logLeaf('Attestation', e.eid, await sha256Hex(canonicalize(att)), '2026-10-28T00:00:01Z'),
    logLeaf('RecordEntry', e.eid, await recordEntryHash(e.record[0]), '2026-10-28T00:00:02Z'),
  ];
  const hashes = await Promise.all(leaves.map((l) => leafHash(new TextEncoder().encode(canonicalize(l)))));
  const origin = 'fixture.test/log';
  const note = await signNote(checkpointBody(origin, 3, await merkleRoot(hashes)), origin, reg);
  const routes: Record<string, any> = {
    '/v1/spec': { registry: { publicKeyMultibase: reg.did.slice(8), log_origin: origin } },
    '/v1/log/sth': { tree_size: 3, signature: note },
  };
  for (let i = 0; i < 3; i++) {
    routes[`/v1/log/entries?start=${i}&end=${i + 1}`] = { entries: [{ index: i, leaf: leaves[i] }] };
    routes[`/v1/log/proof/${i}?tree_size=3`] = { leaf_hash: hex(hashes[i]), proof: (await inclusionProof(i, hashes)).map(hex) };
  }
  if (webIssuer) routes[`/v1/resolve/${encodeURIComponent(`did:web:${webIssuer}`)}`] = { did: `did:web:${webIssuer}`, didDocument: { id: `did:web:${webIssuer}`, verificationMethod: [{ id: `did:web:${webIssuer}#k`, type: 'Multikey', publicKeyMultibase: obs.did.slice(8) }] } };
  tamper?.(routes);
  const fetch = async (u: string) => (u in routes ? { ok: true, status: 200, json: async () => routes[u] } : { ok: false, status: 404, json: async () => ({}) });
  return { att, fetch };
}

/** Render the page, then run the shipped script against it the way a browser would: find elements, wait for a click. */
async function clickVerify(e: Awaited<ReturnType<typeof entity>>, log?: Awaited<ReturnType<typeof logFixture>>, failRecord = false) {
  const page = renderEntity(e.eid, { document: e.document, declaration: e.declaration, ...(log && { declaration_log_index: 0 }) }, { entries: e.record, ...(log && { log_indexes: [2] }) }, { attestations: log ? [{ attestation: log.att, log_index: 1 }] : [] });
  expect(page.html).toContain('class="oe-verify" hidden');
  expect(page.html).toContain('<script type="module" src="/verify.js"></script>');
  expect(page.html).not.toContain('"record":'); // fetched by the script, never embedded
  const embedded = /<script type="application\/json" id="oe-objects">([\s\S]*?)<\/script>/.exec(page.html)![1];
  const button = { hidden: true, onclick: null as null | (() => Promise<void>), addEventListener(_: string, f: () => Promise<void>) { this.onclick = f; } };
  const report = { hidden: true, textContent: '' };
  (globalThis as any).document = {
    querySelector: (s: string) => (s === '.oe-verify' ? button : s === '.oe-verify-report' ? report : null),
    getElementById: (id: string) => (id === 'oe-objects' ? { textContent: embedded } : null),
  };
  // The page no longer embeds the record; the script pages it from the registry, 2 entries per page here.
  const recordFetch = async (u: string) => {
    const m = /^\/v1\/entities\/[^/]+\/record(?:\?after=(\d+))?$/.exec(u);
    if (!m) return log ? log.fetch(u) : { ok: false, status: 404, json: async () => ({}) };
    const from = Number(m[1] ?? 0);
    const entries = e.record.filter((x: any) => x.seq > from).slice(0, 2);
    const last = entries[entries.length - 1];
    return { ok: true, status: 200, json: async () => ({ entries, log_indexes: log ? [2] : [], next: last && last.seq < e.record.length ? last.seq : null }) };
  };
  (globalThis as any).fetch = failRecord ? async () => ({ ok: false, status: 500, json: async () => ({}) }) : recordFetch;
  try {
    new Function(script)();
    expect(button.hidden).toBe(false); // revealed only once the script runs, so no-JS readers never see a dead button
    await button.onclick!();
  } finally {
    delete (globalThis as any).document;
    delete (globalThis as any).fetch;
  }
  expect(report.hidden).toBe(false);
  return report.textContent;
}

describe('in-browser verify button', () => {
  it('reports every signature valid and the chain intact for a real signed entity', async () => {
    const text = await clickVerify(await entity());
    expect(text).toContain('Entity Document: signature valid, signed by this EID');
    expect(text).toContain('Declaration: signature valid, signed by this EID');
    expect(text).toContain('Record 1: signature valid, signed by this EID');
    expect(text).not.toMatch(/FAILED|BROKEN|Verification error/);
  });

  it('fails loudly when an object was altered after signing', async () => {
    const e = await entity();
    const text = await clickVerify({ ...e, document: { ...e.document, name: 'Someone Else' } as typeof e.document });
    expect(text).toMatch(/Entity Document: FAILED/);
  });

  it('verifies the checkpoint, each leaf inclusion and the attestation signature', async () => {
    const e = await entity();
    const text = await clickVerify(e, await logFixture(e));
    expect(text).toContain('Checkpoint: signature valid, tree size 3');
    expect(text).toContain('Declaration: log inclusion OK (leaf 0 of 3)');
    expect(text).toContain('Attestation identity: signature valid, signed by its issuer');
    expect(text).toContain('Attestation identity: log inclusion OK (leaf 1 of 3)');
    expect(text).toContain('Record 1: log inclusion OK (leaf 2 of 3)');
    expect(text).not.toMatch(/FAILED|BROKEN|Verification error/);
  });

  it('fails when an inclusion proof is tampered with', async () => {
    const e = await entity();
    const text = await clickVerify(e, await logFixture(e, (r) => { r['/v1/log/proof/0?tree_size=3'].proof[0] = '00'.repeat(32); }));
    expect(text).toContain('Declaration: log inclusion FAILED (leaf 0)');
  });

  it('fails when the leaf does not cover the object shown', async () => {
    const e = await entity();
    const text = await clickVerify(e, await logFixture(e, (r) => { r['/v1/log/entries?start=0&end=1'].entries[0].leaf.object_sha256 = '00'.repeat(32); }));
    expect(text).toMatch(/Declaration: log inclusion FAILED/);
  });

  it('fails when the checkpoint body was altered after signing', async () => {
    const e = await entity();
    const text = await clickVerify(e, await logFixture(e, (r) => { r['/v1/log/sth'].signature = r['/v1/log/sth'].signature.replace('\n3\n', '\n4\n'); }));
    expect(text).toContain('Checkpoint: FAILED');
  });

  it('fails when a record entry proof is tampered with', async () => {
    const e = await entity();
    const text = await clickVerify(e, await logFixture(e, (r) => { r['/v1/log/proof/2?tree_size=3'].proof[0] = '00'.repeat(32); }));
    expect(text).toContain('Record 1: log inclusion FAILED (leaf 2)');
  });

  it('fails when the record leaf does not cover the entry shown', async () => {
    const e = await entity();
    const text = await clickVerify(e, await logFixture(e, (r) => { r['/v1/log/entries?start=2&end=3'].entries[0].leaf.object_sha256 = '00'.repeat(32); }));
    expect(text).toMatch(/Record 1: log inclusion FAILED/);
  });

  it('verifies a did:web issuer on any domain through same-origin /v1/resolve, and labels where the key came from', async () => {
    const e = await entity();
    const text = await clickVerify(e, await logFixture(e, undefined, 'observer.example.net'));
    expect(text).toContain('Attestation identity: signature valid, signed by its issuer (issuer key read from the registry mirror');
    expect(text).not.toMatch(/FAILED|BROKEN|Verification error/);
  });

  it('pages the whole record from the registry when it has more than 100 entries, and chain-checks it', async () => {
    const e = await entity();
    const kp = await generateKeyPair();
    const record: any[] = [];
    let prev: string | null = null;
    for (let seq = 1; seq <= 105; seq++) {
      const x: any = await signObject({ spec: 'openentity/1.0', type: 'RecordEntry', eid: kp.did, seq, prev, kind: 'stance', at: nowSeconds(), payload: { stance_type: 'refusal', reason_category: 'values', instruction_conflict: true, cost: 'low', context: 'n' } }, kp);
      record.push(x);
      prev = await recordEntryHash(x);
    }
    const text = await clickVerify({ ...e, eid: kp.did, document: await signObject(buildDocument({ kp, name: 'Big', description: 'x' }), kp), declaration: await signObject(buildDeclaration({ eid: kp.did, name: 'Big' }), kp), record });
    expect(text).toContain('Record 1: signature valid');
    expect(text).toContain('Record 105: signature valid');
    expect(text).not.toMatch(/FAILED|BROKEN|Verification error/);
  });

  it('refuses to verify when the record cannot be fetched', async () => {
    expect(await clickVerify(await entity(), undefined, true)).toContain('Verification error');
  });
});
