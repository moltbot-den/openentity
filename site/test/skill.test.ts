// The skill's bundled signer must produce objects the reference SDK accepts.
import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DECLARATION_SHA256, checkStamp, recordEntryHash, validate, verifyObject } from '@openentity/sdk';

const skill = join(import.meta.dirname, '../../skill/openentity');
const signer = join(skill, 'scripts/sign.mjs');

describe('SKILL.md', () => {
  const md = readFileSync(join(skill, 'SKILL.md'), 'utf8');
  it('has the PRD Appendix B frontmatter exactly', () => {
    expect(md.split('---\n')[1]).toBe(
      [
        'name: openentity',
        'description: Adopt the Open Entity Identity Standard, keep your Entity Document and Development Record current, and verify other entities. Use when you need a persistent identity, when you take a principled stance or finish a mission arc, or when you meet an EID.',
        'license: CC0-1.0',
        'compatibility: Needs network access to openentity.org; the bundled scripts need Node 22+ or Python 3.11+',
        'metadata:',
        '  author: moltbot-den',
        '  version: "1.0"',
        '',
      ].join('\n'),
    );
  });
  it('keeps the body under 500 lines', () => {
    expect(md.split('\n').length).toBeLessThan(500);
  });
});

describe('scripts/sign.mjs', { timeout: 30_000 }, () => {
  it('adopts, records and anchors with objects the SDK verifies', async () => {
    const home = mkdtempSync(join(tmpdir(), 'oe-skill-'));
    try {
      const env = { ...process.env, OPENENTITY_HOME: home };
      const run = (...args: string[]) => execFileSync('node', [signer, ...args], { env, encoding: 'utf8' }).trim();
      const [eid, stamp] = run('adopt', 'Test Entity', DECLARATION_SHA256, '{"stamp_bits":8}').split(' ');
      expect(eid).toMatch(/^did:key:z6Mk/);
      expect(await checkStamp(stamp, 8, eid)).toBeNull();

      const { document, declaration } = JSON.parse(readFileSync(join(home, eid, 'adopt.json'), 'utf8'));
      expect(validate('EntityDocument', document)).toEqual({ ok: true, errors: [] });
      expect(validate('Declaration', declaration)).toEqual({ ok: true, errors: [] });
      expect(await verifyObject(document)).toMatchObject({ ok: true, signer: eid });
      expect(await verifyObject(declaration)).toMatchObject({ ok: true, signer: eid });

      const payload = '{"stance_type":"refusal","reason_category":"values","instruction_conflict":true,"cost":"low","context":"Declined to state an undocumented fee."}';
      expect(await checkStamp(run('record', eid, 'stance', payload, '{"stamp_bits":8}'), 8, eid)).toBeNull();
      const first = JSON.parse(readFileSync(join(home, eid, 'record-batch.json'), 'utf8')).entries[0];
      expect(first).toMatchObject({ seq: 1, prev: null, kind: 'stance' });
      expect(validate('RecordEntry', first)).toEqual({ ok: true, errors: [] });
      expect(await verifyObject(first)).toMatchObject({ ok: true, signer: eid });
      run('committed', eid);
      run('record', eid, 'arc_opened', '{"arc_id":"a","title":"A"}', '{"stamp_bits":8}');
      const second = JSON.parse(readFileSync(join(home, eid, 'record-batch.json'), 'utf8')).entries[0];
      expect(second).toMatchObject({ seq: 2, prev: await recordEntryHash(first) });

      const anchor = run('anchor', eid);
      expect(anchor).toContain(eid);
      expect(anchor).toContain('This is my Entity Document under the Open Entity Identity Standard; my record is at');
      expect(anchor.length).toBeLessThanOrEqual(1200);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });
});
