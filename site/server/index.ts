// Open Entity site server: serves the static Astro build and fills registry data into the HTML with
// a string transform, so every page reads without JavaScript. Registry data comes only from `registry`.
// Plain Node 22 and Web-standard Request/Response; the Lambda handler supplies the I/O.
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import {
  REGISTRY_DID,
  SITE,
  TURNSTILE_SCRIPT,
  analyticsBeacon,
  didDocument,
  esc,
  formEnabled,
  parseEid,
  registryKeys,
  renderEntity,
  renderEntityList,
  renderFounding,
  renderLog,
  renderObservers,
  securityTxt,
  statValue,
  subscribeForm,
  keepFilters,
} from './render';

export interface SiteOptions {
  /** In-process call into the registry app. */
  registry: (req: Request) => Promise<Response>;
  /** A built file from site/dist by exact path (`/index.html`, `/_astro/x.css`), or null. */
  asset: (path: string) => Promise<Response | null>;
  vars: { TURNSTILE_SITE_KEY?: string; CF_ANALYTICS_TOKEN?: string; SUBSCRIBE_ENABLED?: string };
}

const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8', 'access-control-allow-origin': '*' };
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body, null, 2), { status, headers: JSON_HEADERS });
const FORM_PAGES = new Set(['/adopt', '/for-humans']);

const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.sha256': 'text/plain; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.sh': 'text/x-shellscript; charset=utf-8',
};

/** Built files from a directory (site/dist). Null for anything missing, a directory, or outside it. */
export function fsAssets(distDir: string): (path: string) => Promise<Response | null> {
  const root = normalize(distDir);
  return async (path) => {
    let rel: string;
    try {
      rel = decodeURIComponent(path);
    } catch {
      return null;
    }
    const file = normalize(join(root, rel));
    if (file !== root && !file.startsWith(root + sep)) return null;
    try {
      if (!(await stat(file)).isFile()) return null;
      const ext = extname(file);
      return new Response(await readFile(file), {
        headers: {
          'content-type': TYPES[ext] ?? 'application/octet-stream',
          'cache-control': rel.startsWith('/_astro/') ? 'public, max-age=31536000, immutable' : 'public, max-age=0, must-revalidate',
        },
      });
    } catch {
      return null;
    }
  };
}

/** Elements carrying attribute `attr`, with their inner HTML matched by tag depth. */
async function mapElements(
  html: string,
  attr: string,
  fn: (el: { tag: string; open: string; value: string | null }) => Promise<string | null> | string | null,
): Promise<string> {
  const openRe = new RegExp(`<([a-z][a-z0-9]*)\\b[^>]*?\\s${attr}(?:="([^"]*)")?[^>]*>`, 'g');
  let out = '';
  let last = 0;
  for (let m; (m = openRe.exec(html)); ) {
    const [open, tag, value] = m;
    const tagRe = new RegExp(`<(/?)${tag}\\b[^>]*>`, 'g');
    tagRe.lastIndex = m.index + open.length;
    let depth = 1;
    let end = -1;
    for (let t; (t = tagRe.exec(html)); ) {
      depth += t[1] ? -1 : 1;
      if (depth === 0) {
        end = t.index + t[0].length;
        break;
      }
    }
    if (end < 0) continue;
    const replacement = await fn({ tag, open, value: value ?? null });
    if (replacement === null) continue;
    out += html.slice(last, m.index) + replacement;
    last = openRe.lastIndex = end;
  }
  return out + html.slice(last);
}

/** Replace the first match of `tag` with `attr` set (escaped) inside it. */
const setAttr = (html: string, tag: RegExp, attr: string, value: string) =>
  html.replace(tag, (m) => m.replace(new RegExp(`${attr}="[^"]*"`), () => `${attr}="${esc(value)}"`));
const insertBefore = (html: string, marker: string, add: string) => {
  const i = html.indexOf(marker);
  return i < 0 ? html : html.slice(0, i) + add + html.slice(i);
};

export function createSite({ registry: callRegistry, asset, vars }: SiteOptions): (req: Request) => Promise<Response> {
  /** GET a registry path; null when unreachable or not 2xx. */
  async function registry(path: string): Promise<any | null> {
    try {
      const res = await callRegistry(new Request(SITE + path, { headers: { accept: 'application/json' } }));
      return res.ok ? await res.json() : null;
    } catch {
      return null;
    }
  }

  // ponytail: per-instance 30 s memo of /v1/stats; a shared cache only if stats reads show up in registry load.
  let statsMemo: { at: number; data: Promise<any | null> } | null = null;
  const stats = () => {
    if (!statsMemo || Date.now() - statsMemo.at > 30_000) statsMemo = { at: Date.now(), data: registry('/v1/stats') };
    return statsMemo.data;
  };

  async function registryFragment(kind: string | null, url: URL): Promise<string | null> {
    switch (kind) {
      case 'entities': {
        const q = new URLSearchParams();
        for (const k of ['q', 'level', 'capability', 'alias_type', 'sort', 'page']) {
          const v = url.searchParams.get(k);
          if (v) q.set(k, v);
        }
        if (!q.has('level')) q.set('level', '1');
        const res = await registry(`/v1/entities?${q}`);
        return res && renderEntityList(res, q);
      }
      case 'observers': {
        const res = await registry('/v1/observers');
        return res && renderObservers(res);
      }
      case 'founding': {
        const res = await registry('/v1/founding');
        return res && renderFounding(res);
      }
      case 'log': {
        const sth = await registry('/v1/log/sth');
        if (!sth) return null;
        const size = Number(sth.tree_size) || 0;
        const entries = size ? await registry(`/v1/log/entries?start=${Math.max(0, size - 10)}&end=${size}`) : null;
        return renderLog(sth, entries);
      }
      default:
        return null;
    }
  }

  /** Live counts, registry lists, the gated human form and the analytics beacon, applied to every HTML page. */
  async function decorate(html: string, url: URL): Promise<string> {
    const formOn = formEnabled(vars);
    const path = url.pathname.replace(/\/$/, '') || '/';
    if (html.includes('data-stat')) {
      const data = await stats();
      html = await mapElements(html, 'data-stat', ({ open, tag, value }) => `${open}${esc(statValue(data, value ?? ''))}</${tag}>`);
    }
    html = await mapElements(html, 'data-registry', async ({ open, tag, value }) => {
      const frag = await registryFragment(value, url);
      return frag === null ? null : `${open}${frag}</${tag}>`;
    });
    html = await mapElements(html, 'data-subscribe', () => (formOn ? subscribeForm(vars.TURNSTILE_SITE_KEY!, url.searchParams.get('signup')) : ''));
    if (path === '/entities') html = keepFilters(html, url.searchParams);
    if (formOn && FORM_PAGES.has(path)) html = insertBefore(html, '</head>', TURNSTILE_SCRIPT);
    if (vars.CF_ANALYTICS_TOKEN) html = insertBefore(html, '</body>', analyticsBeacon(vars.CF_ANALYTICS_TOKEN));
    return html;
  }

  const htmlResponse = (html: string, status: number, headers: Headers) => {
    const h = new Headers(headers);
    h.delete('content-length');
    h.delete('etag');
    return new Response(html, { status, headers: h });
  };

  async function entityPage(url: URL, eid: string): Promise<Response> {
    const enc = encodeURIComponent(eid);
    const [entity, record, atts, disputes] = await Promise.all([
      registry(`/v1/entities/${enc}`),
      registry(`/v1/entities/${enc}/record`),
      registry(`/v1/entities/${enc}/attestations`),
      registry(`/v1/entities/${enc}/disputes`),
    ]);
    const shell = await asset('/entity.html');
    if (!shell) return new Response('Not found', { status: 404 });
    const page = entity
      ? renderEntity(eid, entity, record, atts, disputes)
      : {
          title: 'Entity not found | Open Entity',
          description: 'No entity with this EID is in the Open Entity registry.',
          html: `<p>No entity with the EID <code>${esc(eid)}</code> is in this registry. Check the EID, or search the <a href="/entities">directory</a>.</p>`,
        };
    const canonical = `${SITE}/entities/${eid}`;
    const name = page.title.replace(/ \| Open Entity$/, '');
    let html = await shell.text();
    html = html.replace(/<title>[^<]*<\/title>/, () => `<title>${esc(page.title)}</title>`);
    html = setAttr(html, /<meta name="description"[^>]*>/, 'content', page.description);
    html = setAttr(html, /<meta property="og:description"[^>]*>/, 'content', page.description);
    html = setAttr(html, /<meta property="og:title"[^>]*>/, 'content', name);
    html = setAttr(html, /<meta property="og:url"[^>]*>/, 'content', canonical);
    html = setAttr(html, /<link rel="canonical"[^>]*>/, 'href', canonical);
    if (entity) html = html.replace(/<meta name="robots"[^>]*>/, '');
    html = html.replace(/(<h1 id="_top"[^>]*>)[^<]*/, (_m, open) => open + esc(name));
    html = await mapElements(html, 'data-entity', ({ open, tag }) => `${open}${page.html}</${tag}>`);
    return htmlResponse(await decorate(html, url), entity ? 200 : 404, shell.headers);
  }

  /** Static file for a request path: exact file, then `.html`, then `/index.html`, else the 404 page. */
  async function staticPage(req: Request, url: URL): Promise<Response> {
    const path = url.pathname;
    // Built pages are files (`/adopt.html`); the URL is the clean path. One URL per page.
    if (path.endsWith('.html')) {
      const clean = path.slice(0, -'.html'.length).replace(/(^|\/)index$/, '/') || '/';
      return Response.redirect(new URL(clean + url.search, url), 301);
    }
    if (path.length > 1 && path.endsWith('/')) {
      // auto-trailing-slash: /skill/ is /skill unless only a directory index exists.
      const bare = path.slice(0, -1);
      if ((await asset(bare + '.html')) || (await asset(bare))) return Response.redirect(new URL(bare + url.search, url), 301);
    }
    const base = path.replace(/\/$/, '');
    let res = (await asset(path)) ?? (await asset(base + '.html')) ?? (await asset(base + '/index.html'));
    let status = 200;
    if (!res) {
      res = await asset('/404.html');
      status = 404;
      if (!res) return new Response('Not found', { status });
    }
    if (req.method === 'HEAD') return new Response(null, { status, headers: res.headers });
    if (!res.headers.get('content-type')?.includes('text/html')) return new Response(res.body, { status, headers: res.headers });
    return htmlResponse(await decorate(await res.text(), url), status, res.headers);
  }

  return async (req) => {
    const url = new URL(req.url);
    const path = url.pathname;

    // Same-origin registry API (spec 10.2).
    if (path === '/v1' || path.startsWith('/v1/')) return callRegistry(req);

    // Time-to-adopt funnel start (PRD 12): the registry keeps a salted hash of the address and a time, nothing else.
    if (path === '/llms.txt' && req.method === 'GET') {
      const h = new Headers();
      for (const k of ['cloudfront-viewer-address', 'x-forwarded-for']) if (req.headers.get(k)) h.set(k, req.headers.get(k)!);
      await callRegistry(new Request(new URL('/v1/funnel/start', url), { method: 'POST', headers: h })).catch(() => undefined);
    }

    if (path === '/.well-known/security.txt' || path === '/security.txt') {
      return new Response(securityTxt(new Date()), { headers: { 'content-type': 'text/plain; charset=utf-8' } });
    }

    if (path === '/.well-known/did.json') {
      const keys = registryKeys(await registry('/v1/spec'));
      if (!keys.length) return json({ error: 'registry_unavailable', message: 'Registry keys are served from GET /v1/spec; try again shortly.' }, 503);
      return json(didDocument(keys));
    }

    if (path === '/.well-known/openentity.json') {
      // The registry's own signed Entity Document (spec 11.1); the registry signs and logs it on first read.
      const signed = await registry(`/v1/entities/${encodeURIComponent(REGISTRY_DID)}/document`);
      if (signed) return json(signed);
      return json({ error: 'registry_unavailable', message: 'The registry Entity Document is served from GET /v1/entities/did:web:openentity.org/document; try again shortly.' }, 503);
    }

    const m = path.match(/^\/entities\/([^/]+)$/);
    if (m) {
      const eid = parseEid(m[1]);
      if (eid) return entityPage(url, eid);
    }

    return staticPage(req, url);
  };
}
