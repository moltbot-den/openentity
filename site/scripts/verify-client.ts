// In-browser verifier for /entities/<eid>, bundled to /verify.js by prebuild. Progressive enhancement only:
// the button stays hidden without JavaScript, and the page text never depends on it.
import { verifyObject, recordEntryHash } from '@openentity/sdk';

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
  lines.push('Log inclusion: check with `openentity verify` against a checkpoint you fetched yourself.');
  return lines;
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
