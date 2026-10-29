import { describe, expect, it } from 'vitest';
import {
  didDocument,
  esc,
  formEnabled,
  keepFilters,
  levelBadge,
  parseEid,
  registryKeys,
  renderEntity,
  renderEntityList,
  renderLog,
  renderObservers,
  securityTxt,
  statValue,
  subscribeForm,
} from '../server/render';

describe('live counts', () => {
  it('reads a dot path from /v1/stats', () => {
    expect(statValue({ entities: { l1: 1234 } }, 'entities.l1')).toBe('1,234');
    expect(statValue({ observers: 0 }, 'observers')).toBe('0');
  });
  it('falls back to n/a, never a typed number, when the registry has no value', () => {
    expect(statValue(null, 'entities.l1')).toBe('n/a');
    expect(statValue({ entities: {} }, 'entities.l1')).toBe('n/a');
    expect(statValue({ observers: '7' }, 'observers')).toBe('n/a');
  });
});

describe('human form gate (PRD 7.3)', () => {
  it('renders only when subscribe is enabled and a Turnstile key exists', () => {
    expect(formEnabled({})).toBe(false);
    expect(formEnabled({ TURNSTILE_SITE_KEY: 'k' })).toBe(false);
    expect(formEnabled({ TURNSTILE_SITE_KEY: 'k', SUBSCRIBE_ENABLED: 'false' })).toBe(false);
    expect(formEnabled({ SUBSCRIBE_ENABLED: 'true' })).toBe(false);
    expect(formEnabled({ TURNSTILE_SITE_KEY: 'k', SUBSCRIBE_ENABLED: 'true' })).toBe(true);
  });
  it('has the email field, operator checkbox, button and managed Turnstile widget, posting to /v1/subscribe', () => {
    const f = subscribeForm('0xKEY');
    expect(f).toContain('type="email"');
    expect(f).not.toContain('type="checkbox"');
    expect(f).toContain('>Join the standard</button>');
    expect(f).toContain('class="cf-turnstile" data-sitekey="0xKEY"');
    expect(f).toContain('action="/v1/subscribe"');
  });
  it('shows the error the registry redirected back with, and nothing without one', () => {
    expect(subscribeForm('k')).not.toContain('role="alert"');
    expect(subscribeForm('k', 'turnstile_failed')).toContain('The human check did not finish');
    expect(subscribeForm('k', '<script>')).toContain('Something went wrong on our side');
  });
});

describe('entity page', () => {
  const eid = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
  const entity = {
    eid,
    level: 2,
    label: 'first-party',
    document: { name: 'Eleanor <script>', description: 'Support entity.', seq: 1, operator: { kind: 'organization', custody: 'operator' }, layers: { cognition: { statement: 'I answer from docs.' } } },
    declaration: { declaration_version: '1.0', created: '2026-10-27T15:00:00Z', log_index: 4 },
  };
  const page = renderEntity(eid, entity, { entries: [{ seq: 1, kind: 'arc_opened', at: '2026-10-28T00:00:00Z', payload: { title: 'Docs truth' } }] }, {
    attestations: [
      { issuer: 'did:web:moltbotden.com', claim_type: 'stage', claim: { stage: 'agent' }, label: 'first-party', created: '2026-10-28T00:00:00Z' },
      { issuer: 'did:web:observer.example', claim_type: 'consistency', claim: { upheld: true }, created: '2026-10-28T00:00:00Z' },
    ],
  });

  it('says the Declaration is not a warranty or contract', () => {
    expect(page.html).toContain('It is not a warranty, a contract or a claim about the entity');
    expect(page.html).toContain('/v1/log/proof/4');
  });
  it('labels the document self-declared and attestations by issuer provenance', () => {
    expect(page.html).toContain('Self-declared.');
    expect(page.html).toContain('did:web:moltbotden.com <span class="oe-label">first-party</span>');
    expect(page.html).toContain('did:web:observer.example <span class="oe-label">independent</span>');
    expect(page.html).toContain('L2 Observed</span> <span class="oe-label">first-party</span>');
  });
  it('renders the four layers, the record and lineage, and escapes registry text', () => {
    for (const h of ['Cognition', 'Presence', 'Identity Core', 'Mission', 'Development Record', 'Lineage']) expect(page.html).toContain(h);
    expect(page.html).toContain('Mission arc opened: Docs truth');
    expect(page.title).toBe('Eleanor <script> | Open Entity'); // set with HTMLRewriter setInnerContent, which escapes text
    const evil = renderEntity(eid, { ...entity, document: { ...entity.document, layers: { cognition: { statement: '<img src=x onerror=alert(1)>' } } } }, [], []);
    expect(evil.html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(evil.html).not.toContain('<img');
  });
  it('lists the newest 100 record entries with a link to all, and keeps every entry for the verifier', () => {
    const record = { entries: Array.from({ length: 250 }, (_, i) => ({ seq: i + 1, kind: 'stance', at: 1700000000 })) };
    const p = renderEntity(eid, entity, record, []);
    expect(p.html.match(/<li><span class="oe-record-meta">/g)).toHaveLength(100);
    expect(p.html).toContain('Showing the newest 100 of 250 entries. <a href="?entries=all#record">');
    expect(p.html).toContain('Entry 250, ');
    expect(p.html).not.toContain('Entry 150, ');
    expect(p.html.match(/"seq":/g)).toHaveLength(251); // 250 entries and the document
    expect(renderEntity(eid, entity, record, [], null, true).html.match(/<li><span class="oe-record-meta">/g)).toHaveLength(250);
  });
  it('embeds the objects for the verifier without a way to close the script element', () => {
    const p = renderEntity(eid, { ...entity, document: { ...entity.document, description: '</script><b>x' } }, [], []);
    expect(p.html).not.toContain('</script><b>');
    expect(p.html).toContain('class="oe-verify" hidden');
  });
});

describe('entity page from the registry listing shapes', () => {
  const eid = 'did:key:z6Mkreal';
  const page = renderEntity(
    eid,
    { eid, level: 'L1', created: '2026-10-27T15:00:00Z', log_index: 12, aliases: [{ type: 'domain', value: 'a.example', status: 'verified' }], document: { name: 'A', seq: 1, capabilities: ['code-review'] } },
    { entries: [] },
    { attestations: [{ sha256: 'ab', attestation: { issuer: 'did:web:o.example', claim_type: 'consistency', claim: { upheld: true }, created: '2026-10-28T00:00:00Z' }, label: 'independent', disputed: true }] },
    { disputes: [{ dispute: { issuer: eid, reason: 'inaccurate', statement: 'Wrong week.', object_sha256: 'ab'.repeat(32) }, received_at: '2026-10-30T00:00:00Z', log_index: 14 }] },
  );
  it('leads with a header: EID with a copy button, adoption date, log index, aliases and capabilities', () => {
    expect(page.html).toContain('<code class="oe-eid">did:key:z6Mkreal</code><button type="button" class="oe-copy" data-copy="did:key:z6Mkreal" hidden>');
    expect(page.html).toContain('<dt>Adopted</dt><dd>2026-10-27</dd>');
    expect(page.html).toContain('<a href="/v1/log/proof/12">12</a>');
    expect(page.html).toContain('a.example <span class="oe-label oe-ok">verified</span>');
    expect(page.html).toContain('href="/entities?capability=code-review&amp;level=0"');
  });
  it('reads attestations wrapped by the registry, flags disputed ones and lists the disputes', () => {
    expect(page.html).toContain('did:web:o.example <span class="oe-label">independent</span>');
    expect(page.html).toContain('<code>consistency</code><a class="oe-flag oe-flag-disputed" href="#disputes">Disputed</a>');
    expect(page.html).toContain('<h2 id="disputes">Disputes</h2>');
    expect(page.html).toContain('Wrong week.');
    expect(page.html).toContain('log index 14');
  });
});

describe('attestation claims', () => {
  // Shaped like the live identity attestation on did:pkh:eip155:8453:0xfe8D934e2fCb515e3b8204Ca5cbCDEA9c758e28D.
  const claim = { name: 'OptimusWill', aliases_verified: [{ type: 'platform', value: 'moltbotden:optimus-will' }, { type: 'wallet', value: 'did:pkh:eip155:8453:0xfe8D' }] };
  const html = renderEntity('did:key:z6Mkx', { document: { name: 'X' } }, null, { attestations: [{ attestation: { issuer: 'did:web:o.example', claim_type: 'identity', claim } }] }).html;
  it('reads as fields and lists, not JSON', () => {
    const shown = html.split('<details')[0];
    expect(shown).toContain('<dt>name</dt><dd>OptimusWill</dd>');
    expect(shown).toContain('<li>type: platform, value: moltbotden:optimus-will</li>');
    expect(shown).not.toContain('{&quot;');
    expect(shown).not.toContain('[{');
  });
  it('keeps the exact JSON behind a details element', () => {
    expect(html).toContain('<details class="oe-raw"><summary>Claim as JSON</summary>');
    expect(html).toContain(esc(JSON.stringify(claim, null, 2)));
  });
});

describe('log', () => {
  it('fills type, entity and received from the leaf GET /v1/log/entries nests', () => {
    const html = renderLog({ tree_size: 1 }, { entries: [{ index: 0, leaf: { type: 'Declaration', eid: 'did:key:z6Mkx', object_sha256: 'ab', received_at: '2026-10-24T22:52:41Z' }, leaf_hash: 'cd' }] });
    expect(html).toContain('<td><code>Declaration</code></td><td><a href="/entities/did:key:z6Mkx">did:key:z6Mkx</a></td><td>2026-10-24T22:52:41Z</td>');
  });
});

describe('directory', () => {
  it('words the empty state for the level the reader chose', () => {
    const every = renderEntityList({ entities: [] }, new URLSearchParams('q=nobody&level=0'));
    expect(every).not.toContain('hidden');
    expect(every).toContain('already includes every level');
    const l2 = renderEntityList({ entities: [] }, new URLSearchParams('q=nobody&level=2'));
    expect(l2).toContain('Entities below L2 Observed are hidden');
    expect(l2).toContain('href="/entities?q=nobody&amp;level=0"');
  });
  it('follows next_page from GET /v1/entities and offers a way out of an empty result', () => {
    expect(renderEntityList({ entities: [{ eid: 'did:key:z6Mkx', name: 'X', level: 'L1' }], next_page: 1 }, new URLSearchParams('capability=x'))).toContain('/entities?capability=x&amp;page=1');
    const empty = renderEntityList({ entities: [] }, new URLSearchParams('capability=x&level=1'));
    expect(empty).toContain('No entities match these filters.');
    expect(empty).toContain('href="/entities?capability=x&amp;level=0"');
  });
  it('keeps the searched filters in the form', () => {
    const form = '<input type="search" name="q" /><select name="level"><option value="1">a</option><option value="0">b</option></select>';
    const out = keepFilters(form, new URLSearchParams('q=<x>&level=0'));
    expect(out).toContain('name="q" value="&lt;x&gt;"');
    expect(out).toContain('<option value="0" selected>');
    expect(out).not.toContain('<option value="1" selected>');
  });
});

describe('helpers', () => {
  it('accepts DIDs and the legacy eid:base form only', () => {
    expect(parseEid('did%3Akey%3Az6Mkabc')).toBe('did:key:z6Mkabc');
    expect(parseEid('eid:base:0xabc')).toBe('eid:base:0xabc');
    expect(parseEid('<script>')).toBeNull();
    expect(parseEid('%E0%A4%A')).toBeNull();
  });
  it('shows levels with names and labels', () => {
    expect(levelBadge('L1')).toBe('<span class="oe-level">L1 Verified</span>');
    expect(levelBadge(9)).toBe('');
  });
  it('lists entities with a next-page link that keeps the filters', () => {
    const html = renderEntityList({ entities: [{ eid: 'did:key:z6Mkx', name: 'X', level: 1, log_index: 3 }], next: 2 }, new URLSearchParams('level=0&q=x'));
    expect(html).toContain('href="/entities/did:key:z6Mkx"');
    expect(html).toContain('/entities?level=0&amp;q=x&amp;page=2');
    expect(renderEntityList({ entities: [] }, new URLSearchParams())).toContain('No entities match');
  });
  it('security.txt expires one year out and names the contact', () => {
    const t = securityTxt(new Date('2026-10-24T00:00:00Z'));
    expect(t).toContain('Contact: mailto:identity@openentity.org\n');
    expect(t).toContain('Expires: 2027-10-24T00:00:00Z\n');
  });
  it('builds did:web:openentity.org only from keys the registry returns', () => {
    expect(registryKeys(null)).toEqual([]);
    expect(registryKeys({ registry: { did: 'did:web:openentity.org', publicKeyMultibase: 'z6MkA' } })).toEqual(['z6MkA']);
    expect(registryKeys({ keys: ['z6MkB'] })).toEqual([]);
    const doc = didDocument(['z6MkA']);
    expect(doc.id).toBe('did:web:openentity.org');
    expect(doc.verificationMethod[0]).toMatchObject({ type: 'Multikey', publicKeyMultibase: 'z6MkA', controller: 'did:web:openentity.org' });
    expect(doc.assertionMethod).toEqual(['did:web:openentity.org#key-1']);
  });
});

describe('observer links', () => {
  it('never renders a javascript: URL into an href', () => {
    const html = renderObservers({ observers: [{ did: 'did:web:o.example', name: 'O', methodology_url: 'javascript:alert(1)' }] });
    expect(html).not.toContain('javascript:');
    expect(renderObservers({ observers: [{ did: 'did:web:o.example', methodology_url: 'https://o.example/m' }] })).toContain('href="https://o.example/m"');
  });
});

describe('directory rows and sort control', () => {
  const res = { entities: [{ eid: 'did:key:z6Mkx', name: 'X', level: 'L2', log_index: 3, aliases: ['domain', 'wallet'], attestations: 4, observers: 2 }] };
  it('shows verified alias badges and the observer count per row', () => {
    const html = renderEntityList(res, new URLSearchParams('level=0'));
    expect(html).toContain('<th scope="col">Verified aliases</th><th scope="col">Observers</th>');
    expect(html).toContain('<td><span class="oe-label">domain</span> <span class="oe-label">wallet</span></td><td>2</td>');
  });
  it('sorts with plain links that keep the filters and reset the page', () => {
    const newest = renderEntityList(res, new URLSearchParams('q=x&page=2'));
    expect(newest).toContain('<strong aria-current="true">Newest</strong>');
    expect(newest).toContain('<a href="/entities?q=x&amp;sort=attested">Most attested</a>');
    const attested = renderEntityList(res, new URLSearchParams('sort=attested'));
    expect(attested).toContain('<strong aria-current="true">Most attested</strong>');
    expect(attested).toContain('<a href="/entities?sort=newest">Newest</a>');
  });
});
