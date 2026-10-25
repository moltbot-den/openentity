import { describe, expect, it } from 'vitest';
import {
  didDocument,
  formEnabled,
  levelBadge,
  parseEid,
  registryKeys,
  renderEntity,
  renderEntityList,
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
    expect(f).toContain('I operate AI agents');
    expect(f).toContain('>Join the standard</button>');
    expect(f).toContain('class="cf-turnstile" data-sitekey="0xKEY"');
    expect(f).toContain('action="/v1/subscribe"');
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
  it('embeds the objects for the verifier without a way to close the script element', () => {
    const p = renderEntity(eid, { ...entity, document: { ...entity.document, description: '</script><b>x' } }, [], []);
    expect(p.html).not.toContain('</script><b>');
    expect(p.html).toContain('class="oe-verify" hidden');
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
