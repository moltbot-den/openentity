// Attacker-minded review findings on the site server. Each test fails if its fix is removed.
import { describe, expect, it } from 'vitest';
import { createSite } from '../server';

const shell = '<html><head><title>x</title></head><body><div data-subscribe></div></body></html>';
const site = createSite({
  registry: async () => new Response('{}'),
  asset: async (p) => (p === '/adopt.html' ? new Response(shell, { headers: { 'content-type': 'text/html' } }) : null),
  vars: { SUBSCRIBE_ENABLED: 'true', TURNSTILE_SITE_KEY: 'k' },
});
const get = (path: string) => site(new Request(`https://openentity.org${path}`, { redirect: 'manual' }));

describe('site server hardening', () => {
  it('a .html path with extra leading slashes redirects on this host, never to another one', async () => {
    for (const path of ['//evil.example/x.html', '///evil.example/x.html', '//evil.example/index.html']) {
      const res = await get(path);
      expect(res.status).toBe(301);
      expect(new URL(res.headers.get('location')!, 'https://openentity.org').host).toBe('openentity.org');
    }
  });

  it('?signup= shows a message only for a known code, never a prototype property', async () => {
    const html = await (await get('/adopt?signup=constructor')).text();
    expect(html).not.toContain('native code');
    expect(html).toContain('Something went wrong');
  });
});
