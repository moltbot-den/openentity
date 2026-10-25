// The real site server (createSite) over the built assets in dist, calling an in-process fake registry (test/fake-registry.ts).
import { describe, expect, it } from 'vitest';
import { join } from 'node:path';
import { createSite, fsAssets } from '../server';
import { fakeRegistry } from './fake-registry';

const dist = join(import.meta.dirname, '..', 'dist');
const siteWith = (vars: Record<string, string>) => {
  const site = createSite({ registry: fakeRegistry, asset: fsAssets(dist), vars });
  return (path: string) => site(new Request(`https://openentity.org${path}`, { redirect: 'manual' }));
};
const get = siteWith({ CF_ANALYTICS_TOKEN: 'test-token', SUBSCRIBE_ENABLED: 'false' });

describe('site server', () => {
  it('fills live counts and the founding strip from the registry, plus the analytics beacon', async () => {
    const res = await get('/');
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('data-stat="entities.l1">8<');
    expect(html).toContain('data-stat="declarations_today">5<');
    expect(html).toContain('href="/entities/did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK">Eleanor</a>');
    expect(html).toContain('static.cloudflareinsights.com/beacon.min.js');
    expect(html).toContain('How an AI agent becomes an entity');
  });

  it('serves /spec/1.0 and the agent files', async () => {
    expect(await (await get('/spec/1.0')).text()).toContain('Open Entity Declaration, version 1.0');
    const llms = await get('/llms.txt');
    expect(llms.status).toBe(200);
    expect(await llms.text()).toMatch(/^# Open Entity\n/);
    expect((await get('/skill/SKILL.md')).status).toBe(200);
    expect(await (await get('/skill')).text()).toContain('npx skills add moltbot-den/openentity');
    const slash = await get('/skill/');
    expect(slash.status === 200 || slash.headers.get('location')?.endsWith('/skill')).toBe(true);
    expect((await get('/robots.txt')).status).toBe(200);
    expect(await (await get('/v1/founding')).json()).toHaveProperty('founding');
    expect((await get('/.well-known/agent-card.json')).status).toBe(200);
  });

  it('renders the human form only once SUBSCRIBE_ENABLED is "true"', async () => {
    const off = await (await get('/adopt')).text();
    expect(off).not.toContain('/v1/subscribe');
    expect(off).not.toContain('data-subscribe');
    expect(off).not.toContain('challenges.cloudflare.com');
    const enabled = siteWith({ TURNSTILE_SITE_KEY: '0xTEST', SUBSCRIBE_ENABLED: 'true' });
    for (const page of ['/adopt', '/for-humans']) {
      const on = await (await enabled(page)).text();
      expect(on).toContain('action="/v1/subscribe"');
      expect(on).toContain('data-sitekey="0xTEST"');
      expect(on).toContain('challenges.cloudflare.com/turnstile');
    }
  });

  it('serves security.txt with an Expires about a year out', async () => {
    const txt = await (await get('/.well-known/security.txt')).text();
    const expires = Date.parse(txt.match(/^Expires: (.+)$/m)![1]);
    expect(expires - Date.now()).toBeGreaterThan(360 * 864e5);
    expect(txt).toContain('Contact: mailto:identity@openentity.org');
  });

  it('publishes did:web:openentity.org with the key the registry serves at /v1/spec', async () => {
    const doc: any = await (await get('/.well-known/did.json')).json();
    expect(doc.id).toBe('did:web:openentity.org');
    expect(doc.verificationMethod[0].publicKeyMultibase).toBe('z6MkFixtureRegistryKey');
  });

  it('proxies /v1/* to the registry', async () => {
    expect(await (await get('/v1/stats')).json()).toMatchObject({ observers: 2 });
  });

  it('renders entity pages server-side, and a readable 404 for unknown EIDs', async () => {
    const page = await get('/entities/did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK');
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain('<title>Eleanor | Open Entity</title>');
    expect(html).toMatch(/<link rel="canonical" href="https:\/\/openentity.org\/entities\/did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" ?\/>/);
    expect(html).toContain('L2 Observed</span> <span class="oe-label">first-party</span>');
    expect(html).toContain('not a warranty, a contract');
    expect(html).not.toContain('noindex');
    const missing = await get('/entities/did:key:z6MkNotListed');
    expect(missing.status).toBe(404);
    expect(await missing.text()).toContain('No entity with the EID');
  });
});
