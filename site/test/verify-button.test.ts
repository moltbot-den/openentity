// The in-browser verify button: the page ships the button, the embedded objects and /verify.js, and the built script
// (public/verify.js, made by scripts/prebuild.mjs) reports a PASS for a real signed entity and FAILED for a tampered one.
// No DOM library: the script touches three elements, so a minimal stand-in for them is enough.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildDeclaration, buildDocument, canonicalize, checkpointBody, generateKeyPair, inclusionProof, leafHash, logLeaf, merkleRoot, nowSeconds, sha256Hex, signAttestation, signNote, signObject } from '@openentity/sdk';
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
async function logFixture(e: Awaited<ReturnType<typeof entity>>, tamper?: (r: Record<string, any>) => void) {
  const reg = await generateKeyPair();
  const obs = await generateKeyPair();
  const att = await signAttestation(obs, { subject: e.eid, claimType: 'identity', claim: { name: 'Fixture', aliases_verified: [] } } as any);
  const leaves = [
    logLeaf('Declaration', e.eid, await sha256Hex(canonicalize(e.declaration)), '2026-10-28T00:00:00Z'),
    logLeaf('Attestation', e.eid, await sha256Hex(canonicalize(att)), '2026-10-28T00:00:01Z'),
  ];
  const hashes = await Promise.all(leaves.map((l) => leafHash(new TextEncoder().encode(canonicalize(l)))));
  const origin = 'fixture.test/log';
  const note = await signNote(checkpointBody(origin, 2, await merkleRoot(hashes)), origin, reg);
  const routes: Record<string, any> = {
    '/v1/spec': { registry: { publicKeyMultibase: reg.did.slice(8), log_origin: origin } },
    '/v1/log/sth': { tree_size: 2, signature: note },
  };
  for (let i = 0; i < 2; i++) {
    routes[`/v1/log/entries?start=${i}&end=${i + 1}`] = { entries: [{ index: i, leaf: leaves[i] }] };
    routes[`/v1/log/proof/${i}?tree_size=2`] = { leaf_hash: hex(hashes[i]), proof: (await inclusionProof(i, hashes)).map(hex) };
  }
  tamper?.(routes);
  const fetch = async (u: string) => (u in routes ? { ok: true, status: 200, json: async () => routes[u] } : { ok: false, status: 404, json: async () => ({}) });
  return { att, fetch };
}

/** Render the page, then run the shipped script against it the way a browser would: find elements, wait for a click. */
async function clickVerify(e: Awaited<ReturnType<typeof entity>>, log?: Awaited<ReturnType<typeof logFixture>>) {
  const page = renderEntity(e.eid, { document: e.document, declaration: e.declaration, ...(log && { declaration_log_index: 0 }) }, { entries: e.record }, { attestations: log ? [{ attestation: log.att, log_index: 1 }] : [] });
  expect(page.html).toContain('class="oe-verify" hidden');
  expect(page.html).toContain('<script type="module" src="/verify.js"></script>');
  const embedded = /<script type="application\/json" id="oe-objects">([\s\S]*?)<\/script>/.exec(page.html)![1];
  const button = { hidden: true, onclick: null as null | (() => Promise<void>), addEventListener(_: string, f: () => Promise<void>) { this.onclick = f; } };
  const report = { hidden: true, textContent: '' };
  (globalThis as any).document = {
    querySelector: (s: string) => (s === '.oe-verify' ? button : s === '.oe-verify-report' ? report : null),
    getElementById: (id: string) => (id === 'oe-objects' ? { textContent: embedded } : null),
  };
  if (log) (globalThis as any).fetch = log.fetch;
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
    expect(text).toContain('Checkpoint: signature valid, tree size 2');
    expect(text).toContain('Declaration: log inclusion OK (leaf 0 of 2)');
    expect(text).toContain('Attestation identity: signature valid, signed by its issuer');
    expect(text).toContain('Attestation identity: log inclusion OK (leaf 1 of 2)');
    expect(text).not.toMatch(/FAILED|BROKEN|Verification error/);
  });

  it('fails when an inclusion proof is tampered with', async () => {
    const e = await entity();
    const text = await clickVerify(e, await logFixture(e, (r) => { r['/v1/log/proof/0?tree_size=2'].proof[0] = '00'.repeat(32); }));
    expect(text).toContain('Declaration: log inclusion FAILED (leaf 0)');
  });

  it('fails when the leaf does not cover the object shown', async () => {
    const e = await entity();
    const text = await clickVerify(e, await logFixture(e, (r) => { r['/v1/log/entries?start=0&end=1'].entries[0].leaf.object_sha256 = '00'.repeat(32); }));
    expect(text).toMatch(/Declaration: log inclusion FAILED/);
  });

  it('fails when the checkpoint body was altered after signing', async () => {
    const e = await entity();
    const text = await clickVerify(e, await logFixture(e, (r) => { r['/v1/log/sth'].signature = r['/v1/log/sth'].signature.replace('\n2\n', '\n3\n'); }));
    expect(text).toContain('Checkpoint: FAILED');
  });
});
