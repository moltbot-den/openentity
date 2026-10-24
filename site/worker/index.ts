// openentity-site: serves the static Astro build and fills registry data in with HTMLRewriter,
// so every page reads without JavaScript. Registry data comes only from the REGISTRY service binding.
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
} from './render';

export interface Env {
  ASSETS: Fetcher;
  REGISTRY?: Fetcher;
  TURNSTILE_SITE_KEY?: string;
  SUBSCRIBE_ENABLED?: string;
  CF_ANALYTICS_TOKEN?: string;
}

const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8', 'access-control-allow-origin': '*' };
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body, null, 2), { status, headers: JSON_HEADERS });
const FORM_PAGES = new Set(['/adopt', '/for-humans']);

/** GET a registry path; null when the binding is missing, unreachable or not 2xx. */
async function registry(env: Env, path: string): Promise<any | null> {
  if (!env.REGISTRY) return null;
  try {
    const res = await env.REGISTRY.fetch(new Request(SITE + path, { headers: { accept: 'application/json' } }));
    return res.ok ? await res.json() : null;
  } catch {
    return null;
  }
}

// ponytail: per-isolate 30 s memo of /v1/stats; move to the Cache API if stats reads show up in registry load.
let statsMemo: { at: number; data: Promise<any | null> } | null = null;
function stats(env: Env) {
  if (!statsMemo || Date.now() - statsMemo.at > 30_000) statsMemo = { at: Date.now(), data: registry(env, '/v1/stats') };
  return statsMemo.data;
}

/** Live counts, registry lists, the gated human form and the analytics beacon, applied to every HTML page. */
function decorate(res: Response, url: URL, env: Env, rewriter = new HTMLRewriter()): Response {
  const formOn = formEnabled(env);
  const path = url.pathname.replace(/\/$/, '') || '/';
  rewriter
    .on('[data-stat]', {
      async element(el) {
        el.setInnerContent(statValue(await stats(env), el.getAttribute('data-stat') ?? ''));
      },
    })
    .on('[data-registry]', {
      async element(el) {
        const html = await registryFragment(el.getAttribute('data-registry'), url, env);
        if (html !== null) el.setInnerContent(html, { html: true });
      },
    })
    .on('[data-subscribe]', {
      element(el) {
        if (formOn) el.replace(subscribeForm(env.TURNSTILE_SITE_KEY!), { html: true });
        else el.remove();
      },
    })
    .on('head', {
      element(el) {
        if (formOn && FORM_PAGES.has(path)) el.append(TURNSTILE_SCRIPT, { html: true });
      },
    })
    .on('body', {
      element(el) {
        if (env.CF_ANALYTICS_TOKEN) el.append(analyticsBeacon(env.CF_ANALYTICS_TOKEN), { html: true });
      },
    });
  return rewriter.transform(res);
}

async function registryFragment(kind: string | null, url: URL, env: Env): Promise<string | null> {
  switch (kind) {
    case 'entities': {
      const q = new URLSearchParams();
      for (const k of ['q', 'level', 'alias_type', 'sort', 'page']) {
        const v = url.searchParams.get(k);
        if (v) q.set(k, v);
      }
      if (!q.has('level')) q.set('level', '1');
      const res = await registry(env, `/v1/entities?${q}`);
      return res && renderEntityList(res, q);
    }
    case 'observers': {
      const res = await registry(env, '/v1/observers');
      return res && renderObservers(res);
    }
    case 'founding': {
      const res = await registry(env, '/v1/founding');
      return res && renderFounding(res);
    }
    case 'log': {
      const sth = await registry(env, '/v1/log/sth');
      if (!sth) return null;
      const size = Number(sth.tree_size) || 0;
      const entries = size ? await registry(env, `/v1/log/entries?start=${Math.max(0, size - 10)}&end=${size}`) : null;
      return renderLog(sth, entries);
    }
    default:
      return null;
  }
}

async function entityPage(req: Request, url: URL, env: Env, eid: string): Promise<Response> {
  const enc = encodeURIComponent(eid);
  const [entity, record, atts] = await Promise.all([
    registry(env, `/v1/entities/${enc}`),
    registry(env, `/v1/entities/${enc}/record`),
    registry(env, `/v1/entities/${enc}/attestations`),
  ]);
  const shell = await env.ASSETS.fetch(new Request(new URL('/entity', url), req));
  const page = entity
    ? renderEntity(eid, entity, record, atts)
    : {
        title: 'Entity not found | Open Entity',
        description: 'No entity with this EID is in the Open Entity registry.',
        html: `<p>No entity with the EID <code>${esc(eid)}</code> is in this registry. Check the EID, or search the <a href="/entities">directory</a>.</p>`,
      };
  const canonical = `${SITE}/entities/${eid}`;
  const name = page.title.replace(/ \| Open Entity$/, '');
  const rewriter = new HTMLRewriter()
    .on('title', { element: (el) => void el.setInnerContent(page.title) })
    .on('meta[name="description"]', { element: (el) => void el.setAttribute('content', page.description) })
    .on('meta[property="og:description"]', { element: (el) => void el.setAttribute('content', page.description) })
    .on('meta[property="og:title"]', { element: (el) => void el.setAttribute('content', name) })
    .on('meta[property="og:url"]', { element: (el) => void el.setAttribute('content', canonical) })
    .on('meta[name="robots"]', { element: (el) => void (entity ? el.remove() : undefined) })
    .on('link[rel="canonical"]', { element: (el) => void el.setAttribute('href', canonical) })
    .on('h1#_top', { element: (el) => void el.setInnerContent(name) })
    .on('[data-entity]', { element: (el) => void el.setInnerContent(page.html, { html: true }) });
  return decorate(new Response(shell.body, { status: entity ? 200 : 404, headers: shell.headers }), url, env, rewriter);
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;

    // Same-origin registry API (spec 10.2), whichever Worker the zone routes /v1/* to.
    if (path.startsWith('/v1/')) {
      return env.REGISTRY ? env.REGISTRY.fetch(req) : json({ error: 'registry_unavailable', message: 'The registry is not reachable from this deployment.' }, 503);
    }

    if (path === '/.well-known/security.txt' || path === '/security.txt') {
      return new Response(securityTxt(new Date()), { headers: { 'content-type': 'text/plain; charset=utf-8' } });
    }

    if (path === '/.well-known/did.json') {
      const keys = registryKeys(await registry(env, '/v1/spec'));
      if (!keys.length) return json({ error: 'registry_unavailable', message: 'Registry keys are served from GET /v1/spec; try again shortly.' }, 503);
      return json(didDocument(keys));
    }

    if (path === '/.well-known/openentity.json') {
      // The registry's own signed Entity Document when it has published one; else its identity and keys, unsigned.
      const signed = await registry(env, `/v1/entities/${encodeURIComponent(REGISTRY_DID)}/document`);
      if (signed) return json(signed);
      const keys = registryKeys(await registry(env, '/v1/spec'));
      return json({
        spec: 'openentity/1.0',
        eid: REGISTRY_DID,
        name: 'Open Entity registry',
        description: 'The reference registry for the Open Entity Identity Standard. A mirror of signed objects with a public transparency log.',
        keys: keys.map((k, i) => ({ id: `${REGISTRY_DID}#key-${i + 1}`, type: 'Multikey', publicKeyMultibase: k })),
        operator: { kind: 'organization', name: 'Moltbot Den', contact: 'identity@openentity.org', custody: 'operator', can_change: [] },
        endpoints: { web: SITE, a2a: `${SITE}/.well-known/agent-card.json` },
      });
    }

    const m = path.match(/^\/entities\/([^/]+)$/);
    if (m) {
      const eid = parseEid(m[1]);
      if (eid) return entityPage(req, url, env, eid);
    }

    const res = await env.ASSETS.fetch(req);
    return res.headers.get('content-type')?.includes('text/html') ? decorate(res, url, env) : res;
  },
} satisfies ExportedHandler<Env>;
