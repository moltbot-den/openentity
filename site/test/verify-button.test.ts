// The in-browser verify button: the page ships the button, the embedded objects and /verify.js, and the built script
// (public/verify.js, made by scripts/prebuild.mjs) reports a PASS for a real signed entity and FAILED for a tampered one.
// No DOM library: the script touches three elements, so a minimal stand-in for them is enough.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildDeclaration, buildDocument, generateKeyPair, nowSeconds, signObject } from '@openentity/sdk';
import { renderEntity } from '../server/render';

const script = readFileSync(join(import.meta.dirname, '..', 'public', 'verify.js'), 'utf8');

async function entity() {
  const kp = await generateKeyPair();
  const document = await signObject(buildDocument({ kp, name: 'Verifier Fixture', description: 'Throwaway key, test only.' }), kp);
  const declaration = await signObject(buildDeclaration({ eid: kp.did, name: 'Verifier Fixture' }), kp);
  const e1 = await signObject({ spec: 'openentity/1.0', type: 'RecordEntry', eid: kp.did, seq: 1, prev: null, kind: 'stance', at: nowSeconds(), payload: { stance_type: 'refusal', reason_category: 'values', instruction_conflict: true, cost: 'low', context: 'Declined.' } }, kp);
  return { eid: kp.did, document, declaration, record: [e1] };
}

/** Render the page, then run the shipped script against it the way a browser would: find elements, wait for a click. */
async function clickVerify(e: Awaited<ReturnType<typeof entity>>) {
  const page = renderEntity(e.eid, { document: e.document, declaration: e.declaration }, { entries: e.record }, []);
  expect(page.html).toContain('class="oe-verify" hidden');
  expect(page.html).toContain('<script type="module" src="/verify.js"></script>');
  const embedded = /<script type="application\/json" id="oe-objects">([\s\S]*?)<\/script>/.exec(page.html)![1];
  const button = { hidden: true, onclick: null as null | (() => Promise<void>), addEventListener(_: string, f: () => Promise<void>) { this.onclick = f; } };
  const report = { hidden: true, textContent: '' };
  (globalThis as any).document = {
    querySelector: (s: string) => (s === '.oe-verify' ? button : s === '.oe-verify-report' ? report : null),
    getElementById: (id: string) => (id === 'oe-objects' ? { textContent: embedded } : null),
  };
  try {
    new Function(script)();
    expect(button.hidden).toBe(false); // revealed only once the script runs, so no-JS readers never see a dead button
    await button.onclick!();
  } finally {
    delete (globalThis as any).document;
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
    const text = await clickVerify({ ...e, document: { ...e.document, name: 'Someone Else' } });
    expect(text).toMatch(/Entity Document: FAILED/);
  });
});
