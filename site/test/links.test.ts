// Link check over the built sites (run after `astro build`; verify.sh builds every package before it tests).
// Every same-site href/src must resolve to a built file, and every #fragment to an id in that file. No network.
import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const root = join(import.meta.dirname, '..', '..');
const sites: Record<string, string> = { 'openentity.org': join(root, 'site', 'dist'), 'oeis.dev': join(root, 'site-dev', 'dist') };

// Served by the app Lambda, not built: the registry API, well-known files, and the per-entity pages.
const dynamic = /^\/(v1|\.well-known|entities\/|e\/|mcp)/;

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

function resolve(dist: string, path: string): string | undefined {
  const p = join(dist, decodeURIComponent(path).replace(/\/$/, '')); // the server redirects /x/ to /x
  return [p, p + '.html', join(p, 'index.html')].find((c) => existsSync(c) && statSync(c).isFile());
}

const ids = new Map<string, Set<string>>();
const idsOf = (f: string) => {
  if (!ids.has(f)) ids.set(f, new Set([...readFileSync(f, 'utf8').matchAll(/\s(?:id|name)="([^"]+)"/g)].map((m) => m[1])));
  return ids.get(f)!;
};

describe.each(Object.entries(sites))('%s links', (host, dist) => {
  it.skipIf(!existsSync(dist))('resolve to built files and anchors', () => {
    const pages = walk(dist).filter((f) => f.endsWith('.html') && !relative(dist, f).startsWith('pagefind'));
    const broken: string[] = [];
    for (const page of pages) {
      // Inline script bodies are code, not markup: keep only the opening tag.
      const html = readFileSync(page, 'utf8').replace(/(<script\b[^>]*>)[\s\S]*?<\/script>/g, '$1');
      const from = '/' + relative(dist, page).replace(/\.html$/, '').replace(/(^|\/)index$/, '');
      for (const m of html.matchAll(/\s(?:href|src)="([^"]*)"/g)) {
        const raw = m[1].replace(/&amp;/g, '&');
        if (!raw || /^(mailto:|tel:|data:|javascript:)/.test(raw)) continue;
        const url = new URL(raw, `https://${host}${from}`);
        const target = sites[url.hostname];
        if (!target || dynamic.test(url.pathname)) continue;
        const file = url.pathname === '/' ? join(target, 'index.html') : resolve(target, url.pathname);
        if (!file) broken.push(`${from}: ${raw} has no built file`);
        else if (url.hash.length > 1 && file.endsWith('.html') && !idsOf(file).has(decodeURIComponent(url.hash.slice(1)))) broken.push(`${from}: ${raw} has no such anchor`);
      }
    }
    expect(broken).toEqual([]);
  });
});
