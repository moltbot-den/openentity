// Checks on the built hub (run after `astro build`; `pnpm test` builds first).
import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const hub = join(import.meta.dirname, '..');
const repo = join(hub, '..');
const dist = join(hub, 'dist');

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}
const pages = walk(dist).filter((f) => f.endsWith('.html') && !relative(dist, f).startsWith('pagefind'));
const route = (f: string) => '/' + relative(dist, f).replace(/\.html$/, '').replace(/^index$/, '');
const read = (f: string) => readFileSync(f, 'utf8');
const page = (r: string) => read(join(dist, r === '/' ? 'index.html' : `${r.slice(1)}.html`));
const mainText = (html: string) =>
  html
    .slice(html.indexOf('<main'), html.indexOf('</main>'))
    .replace(/<(script|style)[\s\S]*?<\/\1>/g, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&[a-z#0-9]+;/g, ' ')
    .replace(/\s+/g, ' ');

describe('every page', () => {
  it('has the hub sections', () => {
    const routes = pages.map(route);
    for (const r of ['/', '/contribute', '/propose/claim-type', '/propose/spec-change', '/sdk/typescript', '/sdk/python', '/cli', '/integrations/crewai', '/integrations/openai-agents', '/integrations/vercel-ai', '/integrations/mastra', '/conformance', '/test-vectors', '/registry', '/observers']) {
      expect(routes).toContain(r);
    }
  });

  it.each(pages.filter((f) => route(f) !== '/404').map((f) => [route(f), f]))('%s is canonical on oeis.dev, with one h1 and JSON-LD', (r, f) => {
    const html = read(f);
    expect(html).toMatch(/<meta name="description" content="[^"]{40,}"/);
    expect(html).toContain(`<link rel="canonical" href="https://oeis.dev${r}"/>`);
    expect(html.match(/<h1\b/g)).toHaveLength(1);
    expect(html).toContain('<script type="application/ld+json">');
  });

  it('ships every executable script as a file, so the shared CSP needs no unsafe-inline', () => {
    for (const f of pages) {
      for (const m of read(f).matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
        if (/application\/(ld\+)?json/.test(m[1])) continue;
        expect(m[2].trim(), route(f)).toBe('');
        expect(m[1], route(f)).toMatch(/\bsrc="\/[^/]/);
      }
    }
  });

  it('never hosts the standard: spec links go to openentity.org, and only to sections that exist', () => {
    // Heading ids as Starlight slugs them (github-slugger): lowercase, punctuation dropped, spaces to hyphens.
    const slug = (h: string) => h.toLowerCase().replace(/[^\p{L}\p{N}\- _]/gu, '').replace(/ /g, '-');
    const ids = new Set([...read(join(repo, 'spec/OEIS-1.md')).matchAll(/^#{2,6} (.+)$/gm)].map((m) => slug(m[1])));
    for (const f of pages) {
      const html = read(f);
      expect(html, route(f)).not.toMatch(/href="\/spec\//);
      for (const m of html.matchAll(/href="https:\/\/openentity\.org\/spec\/1\.0#([^"]+)"/g)) expect(ids, `${route(f)} links #${m[1]}`).toContain(m[1]);
    }
  });

  it('links only to hub pages that exist', () => {
    const routes = new Set(pages.map(route));
    for (const f of pages) {
      for (const m of read(f).matchAll(/<a [^>]*href="(\/[^"#?]*)/g)) {
        if (m[1].startsWith('/_astro/') || m[1] === '/sitemap.xml') continue;
        expect(routes, `${route(f)} links ${m[1]}`).toContain(m[1].replace(/(\.html|\/)$/, '') || '/'); // the server 301s /x.html to /x
      }
    }
  });
});

describe('generated reference', () => {
  it('the CLI page carries the built CLI help verbatim, so every command is documented', () => {
    const help = execFileSync(process.execPath, [join(repo, 'cli/dist/cli.js'), '--help'], { encoding: 'utf8' });
    const text = mainText(page('/cli'));
    for (const line of help.split('\n').filter((l) => /^ {2}[a-z]/.test(l))) {
      expect(text).toContain(line.trim().split(' ')[0]);
    }
    expect(text).toContain(help.split('\n')[0].replace(/:.*/, ''));
  });

  it('the SDK pages list every exported function from the source', () => {
    const ts = read(join(repo, 'sdk/ts/src/index.ts'));
    const tsPage = mainText(page('/sdk/typescript'));
    for (const [, name] of ts.matchAll(/^export (?:async )?function (\w+)/gm)) expect(tsPage, name).toContain(`${name}(`);
    const pyPage = mainText(page('/sdk/python'));
    for (const file of ['client.py', 'core.py']) {
      for (const [, name] of read(join(repo, 'sdk/python/openentity', file)).matchAll(/^def ([a-z]\w*)\(/gm)) expect(pyPage, name).toContain(`${name}(`);
    }
  });

  it('the test vectors page lists every committed vector file', () => {
    const text = mainText(page('/test-vectors'));
    for (const f of readdirSync(join(repo, 'test-vectors')).filter((f) => f.endsWith('.json') && !/^log-leaf-\d/.test(f))) expect(text).toContain(f);
  });
});

describe('truth rules', () => {
  // No hand-typed counts in prose: code, the generated reference pages and the protocol parameters the spec fixes are
  // the only places digits may appear.
  const GENERATED = new Set(['/cli', '/test-vectors', '/sdk/typescript', '/sdk/python']);
  const ALLOWED = [
    'Node 22.13 or newer',
    'Python 3.11 or newer',
    'default is 90 days',
    'defaults to 90 days',
    'at least 10 distinct entities',
    '404',
  ];
  const PATTERNS: RegExp[] = [
    /\b\d+(\.\d+)+\b/g, // versions and spec section numbers
    /\b(spec|section|sections|RFC|EIP|ERC|SHA|L)[ -]?\d+\b/gi,
    /\S*[A-Za-z]\d\S*/g,
    /\S*\d[A-Za-z]\S*/g,
  ];
  it.each(pages.map((f) => [route(f), f]).filter(([r]) => !GENERATED.has(r)))('%s states no hand-typed count', (_r, f) => {
    let text = mainText(read(f).replace(/<pre[\s\S]*?<\/pre>/g, ' ').replace(/<code[\s\S]*?<\/code>/g, ' '));
    for (const p of ALLOWED) text = text.split(p).join(' ');
    for (const re of PATTERNS) text = text.replace(re, ' ');
    expect(text.match(/.{0,40}\d.{0,40}/g) ?? []).toEqual([]);
  });
});
