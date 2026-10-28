// Checks on the built site (run after `astro build`; `pnpm test` builds first).
import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const site = join(import.meta.dirname, '..');
const dist = join(site, 'dist');
const repo = join(site, '..');

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}
const files = walk(dist);
const pages = files.filter((f) => f.endsWith('.html') && !relative(dist, f).startsWith('pagefind'));
const route = (f: string) => '/' + relative(dist, f).replace(/\.html$/, '').replace(/^index$/, '');
const read = (f: string) => readFileSync(f, 'utf8');

/** Text of <main> as a reader without JavaScript sees it. */
function mainText(html: string): string {
  const main = html.slice(html.indexOf('<main'), html.indexOf('</main>'));
  return main
    .replace(/<script[\s\S]*?<\/script>/g, ' ')
    .replace(/<style[\s\S]*?<\/style>/g, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&[a-z#0-9]+;/g, ' ')
    .replace(/\s+/g, ' ');
}

describe('llms.txt', () => {
  const llms = read(join(dist, 'llms.txt'));

  it('is PRD Appendix A verbatim', () => {
    const prd = read(join(repo, 'docs/PRD.md'));
    const block = prd.split('## Appendix A')[1].split('```\n')[1];
    expect(llms).toBe(block);
  });

  it('parses per llmstxt.org: H1, blockquote, H2 sections of links only', () => {
    const lines = llms.split('\n');
    expect(lines[0]).toMatch(/^# \S/);
    expect(lines.find((l) => l.trim())).toBe(lines[0]);
    expect(lines.slice(1).find((l) => l.trim())).toMatch(/^> \S/);
    expect(lines.filter((l) => /^# /.test(l))).toHaveLength(1);
    const firstH2 = lines.findIndex((l) => l.startsWith('## '));
    expect(firstH2).toBeGreaterThan(0);
    for (const line of lines.slice(firstH2)) {
      if (!line.trim() || line.startsWith('## ')) continue;
      expect(line).toMatch(/^- \[[^\]]+\]\(https?:\/\/[^)\s]+\)(: .+)?$/);
    }
  });

  it('puts the adopt command before the first H2', () => {
    const cmd = llms.indexOf('npx openentity@latest adopt');
    expect(cmd).toBeGreaterThan(-1);
    expect(cmd).toBeLessThan(llms.indexOf('\n## '));
  });
});

describe('every page', () => {
  it('found the pages of PRD 7.1', () => {
    const routes = pages.map(route);
    for (const r of ['/', '/adopt', '/spec/1.0', '/entities', '/log', '/observers', '/framework', '/research', '/for-humans', '/become', '/faq', '/founding', '/skill', '/subscribed']) {
      expect(routes).toContain(r);
    }
  });

  it.each(pages.map((f) => [route(f), f]))('%s has title, description, canonical, OpenGraph and JSON-LD', (r, f) => {
    const html = read(f);
    expect(html).toMatch(/<title>[^<]+<\/title>/);
    expect(html).toMatch(/<meta name="description" content="[^"]{40,}"/);
    expect(html).toMatch(/<meta property="og:title" content="[^"]+"/);
    if (r !== '/404') {
      const path = r === '/' ? '/' : r;
      expect(html).toContain(`<link rel="canonical" href="https://openentity.org${path}"/>`);
      expect(html).toMatch(/<script type="application\/ld\+json">\{"@context":"https:\/\/schema.org","@type":"Organization"/);
    }
  });

  it('has the JSON-LD types PRD 7.1 names', () => {
    expect(read(join(dist, 'spec/1.0.html'))).toContain('"@type":"TechArticle"');
    expect(read(join(dist, 'index.html'))).toContain('"@type":"Dataset"');
  });

  // Text a reader must see with JavaScript off, straight from the static HTML.
  const expected: Record<string, string[]> = {
    '/': ['How an AI agent becomes an entity', 'npx openentity@latest adopt --name', '--agree', 'Operator transparency', 'For humans'],
    '/adopt': ['npx openentity@latest adopt --name', '--agree', 'https://mcp.openentity.org/mcp', 'curl https://openentity.org/v1/spec', 'uvx openentity adopt', 'entity_adopt_openentity', 'Read https://openentity.org/llms.txt and adopt'],
    '/spec/1.0': ['Open Entity Declaration, version 1.0', 'Entity Identifier', 'Transparency log'],
    '/entities': ['L1 Verified and above', 'Search the directory'],
    '/log': ['tlog-tiles', 'inclusion proof'],
    '/observers': ['first-party', 'Become an observer'],
    '/framework': ['Identity Core', 'Friction', 'Navigation', 'Crystallization', 'No peer-reviewed study has validated'],
    '/research': ['arXiv 2610.01490', 'Claims this site does not make', 'history.csv'],
    '/for-humans': ['Read https://openentity.org/llms.txt and adopt'],
    '/become': ['L1 Verified', 'Agent Secret Store', 'custom:securemyagent:security_posture', 'No tool, payment or platform can make an agent an Entity'],
    '/faq': ['key', 'Moltbot Den'],
    '/founding': ['Founding Entities'],
  };
  it.each(Object.entries(expected))('%s reads without JavaScript', (r, phrases) => {
    const text = mainText(read(join(dist, r === '/' ? 'index.html' : `${r.slice(1)}.html`)));
    for (const p of phrases) expect(text).toContain(p);
  });

  it('links only to spec sections that exist', () => {
    const ids = new Set([...read(join(dist, 'spec/1.0.html')).matchAll(/ id="([^"]+)"/g)].map((m) => m[1]));
    for (const f of pages) {
      for (const m of read(f).matchAll(/href="\/spec\/1\.0#([^"]+)"/g)) expect(ids, `${route(f)} links #${m[1]}`).toContain(m[1]);
    }
  });

  it('links the site title to /, and names every form field', () => {
    for (const f of pages) {
      const html = read(f);
      expect(html, route(f)).toMatch(/<a href="\/" class="site-title/);
      for (const m of html.matchAll(/<(input|select|textarea)\b[^>]*>/g)) expect(m[0], route(f)).toMatch(/\s(id|name)="[^"]+"/);
    }
  });

  it('ships every executable script as a file, so the CSP needs no unsafe-inline for scripts', () => {
    for (const f of pages) {
      for (const m of read(f).matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
        if (/application\/(ld\+)?json/.test(m[1])) continue;
        expect(m[2].trim(), `${route(f)}: <script${m[1]}>`).toBe('');
        expect(m[1], route(f)).toMatch(/\bsrc="\/[^/]/);
      }
    }
  });

  it('keeps the entity template out of the sitemap and search engines', () => {
    expect(files).not.toContain(join(dist, 'sitemap-0.xml'));
    expect(read(join(dist, 'entity.html'))).toContain('<meta name="robots" content="noindex"/>');
  });

  it('ships no human form in the static build (the server adds it only when enabled)', () => {
    for (const f of pages) expect(read(f)).not.toContain('/v1/subscribe');
    for (const r of ['adopt', 'for-humans']) expect(read(join(dist, `${r}.html`))).toContain('data-subscribe');
  });
});

describe('home page', () => {
  const home = read(join(dist, 'index.html'));
  const text = (s: string) =>
    s.replace(/&quot;/g, '"').replace(/&lt;|&#x3C;/gi, '<').replace(/&gt;/g, '>').replace(/&#39;/g, "'").replace(/&amp;/g, '&');

  it('has exactly one h1, as does every page', () => {
    for (const f of pages) expect(read(f).match(/<h1\b/g), route(f)).toHaveLength(1);
  });

  it('copies the exact command each door shows, never "true" or nothing', () => {
    const doors = [...home.matchAll(/<li><span class="oe-door">([^<]*)<\/span>([\s\S]*?)<button[^>]*\bdata-copy="([^"]*)"[^>]*>[^<]*<\/button><\/li>/g)];
    expect(doors.map((d) => d[1])).toEqual(['Shell', 'MCP', 'HTTP']);
    for (const [, door, shown, copy] of doors) {
      const value = text(copy);
      expect(value, door).not.toMatch(/^(true)?$/);
      expect([...shown.matchAll(/<code>([^<]*)<\/code>/g)].map((m) => text(m[1])), door).toContain(value);
    }
    expect(text(doors[0][3])).toBe('npx openentity@latest adopt --name "<your name>" --agree');
  });

  it('shows the HTTP adopt endpoint as text and links the HTTP guide', () => {
    expect(home).not.toContain('href="https://openentity.org/v1/adopt"');
    expect(home).toContain('href="/guides/adopt-http"');
  });
});

describe('truth rules', () => {
  it('has no em dash in any built file', () => {
    const EM_DASH = Buffer.from(String.fromCharCode(0x2014));
    const text = files.filter((f) => /\.(html|txt|md|json|js|mjs|css|xml|svg|sh|sha256)$/.test(f));
    const bad = text.filter((f) => readFileSync(f).includes(EM_DASH));
    expect(bad.map((f) => relative(dist, f))).toEqual([]);
  });

  // No hand-typed counts: after removing data-stat elements, code, and the allowed literals below,
  // no digit may remain in a page's visible text. The spec page is exempt: it is the normative text,
  // and its numbers are protocol parameters, not counts.
  const EXEMPT = new Set(['/spec/1.0']);
  const ALLOWED_PHRASES = [
    // Research findings quoted with their sources (/research).
    'reduced it by about 87 percent',
    'median 25 percent probability',
    // Observation-profile thresholds from spec 8.5 (/framework) and accreditation rule from spec 8.4 (/observers).
    'Fewer than 10 quality events',
    'At least 10 quality events, at least 1 principled stance',
    'At least 50 quality events, at least 5 principled stances',
    'at least 10 distinct entities',
    // The not-found page title.
    '404',
    // Runtime requirements.
    'Node 22.13 or newer',
    'Node 22+',
  ];
  const ALLOWED_PATTERNS: RegExp[] = [
    /\b\d{4}-\d{2}(-\d{2}(T[\d:]+Z)?)?\b/g, // dates and year-months
    /\b(19|20)\d{2}\b/g, // years
    /\b\d+(\.\d+)+\b/g, // versions, spec section numbers, decimals, arXiv ids
    /\b(section|sections|RFC|EIP|ERC|SHA|OEIS|L)[ -]?\d+\b/gi, // spec sections and standard identifiers
    /\S*[A-Za-z]\d\S*/g, // identifiers mixing letters and digits (Ed25519, eip155, z6Mk, did:key)
    /\S*\d[A-Za-z]\S*/g,
  ];
  it.each(pages.map((f) => [route(f), f]).filter(([r]) => !EXEMPT.has(r)))('%s states no hand-typed count', (_r, f) => {
    let text = mainText(
      read(f)
        .replace(/<(\w+)[^>]*\bdata-stat="[^"]*"[^>]*>[\s\S]*?<\/\1>/g, ' ')
        .replace(/ data-code="[^"]*"/g, '')
        .replace(/<pre[\s\S]*?<\/pre>/g, ' ')
        .replace(/<code[\s\S]*?<\/code>/g, ' ')
        .replace(/<a [^>]*href="https:\/\/arxiv[^"]*"[^>]*>[^<]*<\/a>/g, ' '),
    );
    for (const p of ALLOWED_PHRASES) text = text.split(p).join(' ');
    for (const re of ALLOWED_PATTERNS) text = text.replace(re, ' ');
    expect(text.match(/.{0,40}\d.{0,40}/g) ?? []).toEqual([]);
  });

  it('renders data-stat placeholders as n/a, never as a number', () => {
    for (const f of pages) {
      for (const m of read(f).matchAll(/data-stat="[^"]+"[^>]*>([^<]*)</g)) expect(m[1]).toBe('n/a');
    }
  });
});

describe('copied artifacts', () => {
  it('serves the Declaration and schemas from spec/', () => {
    expect(read(join(dist, 'spec/declaration/1.0.txt'))).toBe(read(join(repo, 'spec/declaration-1.0.txt')));
    expect(read(join(dist, 'spec/declaration/1.0.sha256'))).toBe(read(join(repo, 'spec/declaration-1.0.sha256')));
    expect(JSON.parse(read(join(dist, 'spec/1.0.json')))).toEqual(JSON.parse(read(join(repo, 'spec/schemas/openentity-1.0.json'))));
  });

  it('serves the skill, AGENTS.md, robots.txt, sitemap and agent card', () => {
    expect(read(join(dist, 'skill/SKILL.md'))).toBe(read(join(repo, 'skill/openentity/SKILL.md')));
    for (const s of ['adopt.sh', 'record.sh', 'anchor.sh', 'sign.mjs']) expect(files).toContain(join(dist, 'skill/scripts', s));
    const prd = read(join(repo, 'docs/PRD.md'));
    expect(read(join(dist, 'AGENTS.md'))).toBe(prd.split('### 7.4')[1].split('```\n')[1]);
    const robots = read(join(dist, 'robots.txt'));
    expect(robots).toContain('User-agent: *\n');
    expect(robots).toContain('Allow: /\n');
    expect(robots).toContain('Content-Signal: search=yes, ai-input=yes, ai-train=yes');
    expect(robots).not.toMatch(/Disallow: \/\S/);
    const sitemap = read(join(dist, 'sitemap.xml'));
    expect(sitemap).toContain('<loc>https://openentity.org/spec/1.0</loc>');
    expect(sitemap).not.toContain('/entity<');
    const card = JSON.parse(read(join(dist, '.well-known/agent-card.json')));
    expect(card.capabilities.extensions).toContainEqual(
      expect.objectContaining({ uri: 'https://openentity.org/spec/1.0', required: false, params: expect.objectContaining({ eid: 'did:web:openentity.org' }) }),
    );
  });

  it('builds llms-full.txt from llms.txt, every page and the spec', () => {
    const full = read(join(dist, 'llms-full.txt'));
    expect(full.startsWith('# Open Entity\n')).toBe(true);
    expect(full).toContain('Open Entity Declaration, version 1.0');
    expect(full).toContain('# For humans and operators');
    expect(full).not.toMatch(/<\/?(div|span|ol|li|dl|dt|dd)\b/);
  });
});
