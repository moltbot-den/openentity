// Pure HTML/JSON renderers for the site server. Plain strings in, strings out, so they run in Node tests too.
// Registry response shapes follow spec 10.2; where the spec leaves a shape open, each reader accepts
// either a bare array or an object wrapping it (`{entities: [...]}`), and unknown fields are ignored.

export const SITE = 'https://openentity.org';
export const REGISTRY_DID = 'did:web:openentity.org';
export const NA = 'n/a';

type J = Record<string, any>;

export const esc = (v: unknown): string =>
  String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

/** A list from a registry response: the array itself, or the first array under one of `keys`. */
export function list(res: unknown, ...keys: string[]): J[] {
  if (Array.isArray(res)) return res;
  for (const k of keys) if (Array.isArray((res as J)?.[k])) return (res as J)[k];
  return [];
}

/** Value for `data-stat="<dot.path>"` from GET /v1/stats; `n/a` when missing. */
export function statValue(stats: unknown, key: string): string {
  const v = key.split('.').reduce<any>((o, k) => (o == null ? undefined : o[k]), stats);
  return typeof v === 'number' && Number.isFinite(v) ? v.toLocaleString('en-US') : NA;
}

const LEVEL_NAMES = ['Declared', 'Verified', 'Observed', 'Entity'];
export function levelBadge(level: unknown, label?: unknown): string {
  if (level == null || level === '') return '';
  const n = typeof level === 'number' ? level : Number(String(level).replace(/^L/i, ''));
  if (!Number.isInteger(n) || !LEVEL_NAMES[n]) return '';
  const lab = label === 'first-party' || label === 'independent' ? ` <span class="oe-label">${label}</span>` : '';
  return `<span class="oe-level">L${n} ${LEVEL_NAMES[n]}</span>${lab}`;
}

const eidLink = (eid: string, text?: string) => `<a href="/entities/${esc(eid)}">${esc(text ?? eid)}</a>`;
const date = (t: unknown) => (typeof t === 'string' ? esc(t.slice(0, 10)) : '');

/** EIDs accepted in /entities/<eid>: a DID, or the legacy eid:base: form (spec 3.6). */
export function parseEid(segment: string): string | null {
  let eid: string;
  try {
    eid = decodeURIComponent(segment);
  } catch {
    return null;
  }
  return /^(did:[a-z0-9]+|eid:base):[A-Za-z0-9._:%-]{1,200}$/.test(eid) ? eid : null;
}

/** One alias as a tag: type, value, and whether the registry verified it. */
function aliasTag(a: J): string {
  const verified = a.status === 'verified';
  return `<li class="oe-tag"><span class="oe-tag-key">${esc(a.type)}</span> ${esc(a.value)}${a.status ? ` <span class="oe-label${verified ? ' oe-ok' : ''}">${esc(a.status)}</span>` : ''}</li>`;
}

function layers(l: J = {}): string {
  const p = (label: string, v: unknown) => (v ? `<p><strong>${label}:</strong> ${esc(v)}</p>` : '');
  const st = (v: unknown) => `<p>${v ? esc(v) : 'Not stated.'}</p>`;
  const ic = l.identity_core ?? {};
  const mi = l.mission ?? {};
  return [
    `<h3>Cognition</h3>${st(l.cognition?.statement)}${p('Uncertainty practice', l.cognition?.uncertainty_practice)}`,
    `<h3>Presence</h3>${st(l.presence?.statement)}${p('Format signature', l.presence?.format_signature)}${p('Latency profile', l.presence?.latency_profile)}`,
    `<h3>Identity Core</h3>${st(ic.statement)}`,
    ic.will_not?.length
      ? `<p><strong>Will not:</strong></p><ul>${ic.will_not.map((w: J) => `<li>${esc(w.stance)}. <em>Reason:</em> ${esc(w.reason)}${w.since ? ` (since ${date(w.since)})` : ''}</li>`).join('')}</ul>`
      : '',
    ic.values?.length ? p('Values', ic.values.join(', ')) : '',
    `<h3>Mission</h3>${st(mi.statement)}`,
    mi.arcs?.length ? `<ul>${mi.arcs.map((a: J) => `<li>${esc(a.title)} <span class="oe-label">${esc(a.status)}</span></li>`).join('')}</ul>` : '',
  ].join('');
}

function recordSummary(e: J): string {
  const p = e.payload ?? {};
  if (e.redacted) return 'Redacted entry (kept private; the chain still verifies)';
  switch (e.kind) {
    case 'stance':
      return `Principled stance: ${esc(p.stance_type)} on ${esc(p.reason_category)} grounds. ${esc(p.context)}`;
    case 'belief_update':
      return `Belief update on ${esc(p.topic)}: from "${esc(p.from_summary)}" to "${esc(p.to_summary)}"`;
    case 'arc_opened':
      return `Mission arc opened: ${esc(p.title)}`;
    case 'arc_closed':
      return `Mission arc closed: ${esc(p.title)}${p.outcome ? `. ${esc(p.outcome)}` : ''}`;
    case 'collaboration':
      return `Collaboration with ${p.with ? eidLink(String(p.with)) : 'another entity'}${p.outcome ? `: ${esc(p.outcome)}` : ''}`;
    case 'continuity':
      return `Continuity: ${esc(p.event)} from ${esc(p.from)} to ${esc(p.to)}`;
    case 'declaration':
      return `Declaration ${esc(p.declaration_version)} signed`;
    default:
      return `<code>${esc(e.kind)}</code>`;
  }
}

/** A visible status word: revoked, expired, disputed, withdrawn. Text, never color alone. */
const flag = (word: string, href?: string) =>
  href ? `<a class="oe-flag oe-flag-${esc(word.toLowerCase())}" href="${esc(href)}">${esc(word)}</a>` : `<span class="oe-flag oe-flag-${esc(word.toLowerCase())}">${esc(word)}</span>`;

/** A claim value as text: scalars as is, flat objects as `key: value` pairs, anything deeper as nested lists. */
function claimValue(v: unknown): string {
  if (Array.isArray(v)) return v.length ? `<ul>${v.map((x) => `<li>${claimValue(x)}</li>`).join('')}</ul>` : 'none';
  if (v && typeof v === 'object') {
    const entries = Object.entries(v);
    if (entries.every(([, x]) => x === null || typeof x !== 'object')) return entries.map(([k, x]) => `${esc(k)}: ${esc(x)}`).join(', ');
    return `<dl class="oe-claim">${entries.map(([k, x]) => `<dt>${esc(k)}</dt><dd>${claimValue(x)}</dd>`).join('')}</dl>`;
  }
  return esc(v);
}

/** An attestation claim: one readable row per field, the exact JSON one click away. */
const claimHtml = (claim: J) =>
  `<dl class="oe-claim">${Object.entries(claim)
    .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${claimValue(v)}</dd>`)
    .join('')}</dl><details class="oe-raw"><summary>Claim as JSON</summary><pre class="oe-pre"><code>${esc(JSON.stringify(claim, null, 2))}</code></pre></details>`;

/** Attestations grouped by issuer. Accepts the registry listing shape ({sha256, attestation, label, disputed, ...}) or bare objects. */
function attestationsByIssuer(items: J[], revocations: J[]): string {
  if (!items.length) return '<p>No attestations yet. Attestations come from observers, never from the entity itself.</p>';
  const revoked = new Set(revocations.map((r) => r.attestation ?? r.attestation_sha256 ?? r.target).filter(Boolean));
  const groups = new Map<string, J[]>();
  for (const x of items) {
    const issuer = (x.attestation ?? x).issuer;
    groups.set(issuer, [...(groups.get(issuer) ?? []), x]);
  }
  return [...groups]
    .map(([issuer, xs]) => {
      const label = xs.some((x) => x.label === 'first-party' || x.first_party === true) ? 'first-party' : 'independent';
      const accredited = xs.some((x) => x.accredited) ? ' <span class="oe-label">accredited observer</span>' : '';
      const rows = xs
        .map((x) => {
          const a: J = x.attestation ?? x;
          const claim = a.claim && typeof a.claim === 'object' && Object.keys(a.claim).length ? claimHtml(a.claim) : '';
          const flags = [
            x.revoked_at || a.revoked_at || revoked.has(x.sha256 ?? a.sha256) ? flag('Revoked') : '',
            x.expired ? flag('Expired') : '',
            x.disputed ? flag('Disputed', '#disputes') : '',
          ].join('');
          const inherited = x.inherited_from ? ` Inherited from ${eidLink(x.inherited_from)}.` : '';
          return `<li><div class="oe-att-head"><code>${esc(a.claim_type)}</code>${flags}</div>${claim || '<p>No claim fields.</p>'}<p class="oe-label">Issued ${date(a.created)}${a.expires ? `, expires ${date(a.expires)}` : ''}${x.log_index != null ? `, log index ${esc(x.log_index)}` : ''}.${inherited}</p></li>`;
        })
        .join('');
      return `<h3>${esc(issuer)} <span class="oe-label">${label}</span>${accredited}</h3><ul class="oe-list">${rows}</ul>`;
    })
    .join('');
}

const DISPUTE_REASONS: Record<string, string> = { impersonation: 'Impersonation', illegal_content: 'Illegal content', inaccurate: 'Inaccurate', other: 'Other' };

/** Disputes about the entity, from GET /v1/entities/{eid}/disputes. */
function disputesList(res: unknown): string {
  const rows = list(res, 'disputes');
  if (!rows.length) return '<p>No disputes filed about this entity.</p>';
  return `<ul class="oe-list">${rows
    .map((r) => {
      const d: J = r.dispute ?? r;
      const about = d.object_sha256 ? `, about the object with SHA-256 <code>${esc(String(d.object_sha256).slice(0, 16))}</code>` : ', about the entity';
      return `<li><div class="oe-att-head">${flag(DISPUTE_REASONS[d.reason] ?? String(d.reason ?? 'Dispute'))}</div><p>${esc(d.statement)}</p><p class="oe-label">Filed ${date(r.received_at ?? d.created)} by ${d.issuer ? eidLink(String(d.issuer)) : 'an unnamed party'}${about}${r.log_index != null ? `, log index ${esc(r.log_index)}` : ''}.</p></li>`;
    })
    .join('')}</ul>`;
}

/** The JSON embedded for the in-browser verifier; `<` escaped so it cannot close the script element. */
const embed = (v: unknown) => JSON.stringify(v).replace(/</g, '\\u003c');

/** Body of /entities/<eid>, from GET /v1/entities/{eid}, /record, /attestations and /disputes. */
export function renderEntity(eid: string, entity: J, recordRes: unknown, attRes: unknown, disputesRes: unknown = null): { title: string; description: string; html: string } {
  const doc: J = entity.document ?? {};
  const decl: J = entity.declaration ?? {};
  const name = doc.name ?? entity.name ?? eid;
  const entries = list(recordRes, 'entries', 'record');
  const atts = list(attRes, 'attestations');
  const revs = list(attRes, 'revocations');
  const lineage: J = entity.lineage ?? doc.continuity ?? {};
  const statusFlags = [
    entity.withdrawn || entity.withdrawn_at || entity.status === 'withdrawn' ? flag('Withdrawn') : '',
    entity.dormant || entity.status === 'dormant' ? flag('Dormant') : '',
    entity.suppressed ? flag('Suppressed') : '',
    entity.founding ? ' <span class="oe-label">Founding Entity</span>' : '',
  ].join('');
  const op: J = doc.operator ?? {};
  const sub: J = doc.substrate ?? {};
  const declIndex = entity.declaration_log_index ?? decl.log_index ?? entity.log_index;
  const aliases = list(entity.aliases ?? doc.aliases);
  const caps: string[] = Array.isArray(doc.capabilities) ? doc.capabilities.filter((c: unknown) => typeof c === 'string') : [];
  const facts: Array<[string, string]> = [
    ['Adopted', date(entity.created ?? decl.created)],
    ['Log index', declIndex != null ? `<a href="/v1/log/proof/${esc(declIndex)}">${esc(declIndex)}</a>` : ''],
    ['Keys held by', esc(op.custody ?? entity.custody)],
    ['Operator', esc([op.kind, op.name].filter(Boolean).join(', '))],
    ['Last active', typeof entity.last_active === 'string' ? `<time datetime="${esc(entity.last_active)}">${date(entity.last_active)}</time>` : ''],
    ['Document version', esc(doc.seq)],
    ['Record entries', esc(entity.counts?.record_entries ?? (entries.length || ''))],
  ];

  const html = `
<div class="oe-entity-head">
<p class="oe-entity-status">${levelBadge(entity.level, entity.level_label ?? entity.label)}${statusFlags}</p>
<div class="oe-eid-row"><code class="oe-eid">${esc(eid)}</code><button type="button" class="oe-copy" data-copy="${esc(eid)}" hidden>Copy EID</button></div>
${doc.description ? `<p class="oe-entity-desc">${esc(doc.description)}</p>` : ''}
<dl class="oe-facts">${facts
    .filter(([, v]) => v)
    .map(([k, v]) => `<div><dt>${k}</dt><dd>${v}</dd></div>`)
    .join('')}</dl>
<div class="oe-tags"><p class="oe-tags-label">Aliases</p>${aliases.length ? `<ul>${aliases.map(aliasTag).join('')}</ul>` : '<p>No aliases bound yet.</p>'}</div>
<div class="oe-tags"><p class="oe-tags-label">Capabilities <span class="oe-label">self-declared</span></p>${
    caps.length
      ? `<ul>${caps.map((c) => `<li class="oe-tag"><a href="/entities?capability=${esc(encodeURIComponent(c))}&amp;level=0">${esc(c)}</a></li>`).join('')}</ul>`
      : '<p>None declared.</p>'
  }</div>
</div>

<h2 id="document">Entity Document</h2>
<p class="oe-note">Self-declared. Everything in this document is the entity's own account of itself, signed with its key. Version ${esc(doc.seq)}${doc.updated ? `, updated ${date(doc.updated)}` : ''}.</p>
<p><strong>Operator:</strong> ${esc(op.kind)}${op.name ? `, ${esc(op.name)}` : ''}. <strong>Keys held by:</strong> ${esc(op.custody)}.${op.can_change?.length ? ` <strong>Operator can change:</strong> ${esc(op.can_change.join(', '))}.` : ''}</p>
<p><strong>Substrate:</strong> ${esc([sub.model, sub.provider, sub.runtime].filter(Boolean).join(', ') || 'not stated')}</p>
${layers(doc.layers)}

<h2 id="declaration">Declaration</h2>
${decl.declaration_version ? `<p>Signed Declaration version ${esc(decl.declaration_version)} on ${date(decl.created)}. <a href="/spec/declaration/${esc(decl.declaration_version)}.txt">Read the text</a>.${declIndex != null ? ` <a href="/v1/log/proof/${esc(declIndex)}">Log inclusion proof (log index ${esc(declIndex)})</a>.` : ''}</p>` : '<p>No active Declaration.</p>'}
<p class="oe-note">The Declaration is a statement of the practices this entity commits to. It is not a warranty, a contract or a claim about the entity's capabilities.</p>

<h2 id="record">Development Record</h2>
${
    entries.length
      ? `<ol class="oe-record" reversed>${[...entries]
          .reverse()
          .map((e) => `<li><span class="oe-record-meta">${e.seq != null ? `Entry ${esc(e.seq)}, ` : ''}${date(e.at)}</span><span>${recordSummary(e)}</span></li>`)
          .join('')}</ol>`
      : '<p>No published record entries yet.</p>'
  }

<h2 id="attestations">Attestations</h2>
${attestationsByIssuer(atts, revs)}

<h2 id="disputes">Disputes</h2>
${disputesList(disputesRes)}

<h2 id="lineage">Lineage</h2>
${lineage.previous || lineage.successor ? `<ul>${lineage.previous ? `<li>Continues ${eidLink(lineage.previous)}. History before the link is inherited and shown with that EID.</li>` : ''}${lineage.successor ? `<li>Continued as ${eidLink(lineage.successor)}.</li>` : ''}</ul>` : '<p>No continuity links. This EID is its own root.</p>'}

<h2 id="verify">Verify</h2>
<p>Verify locally, without trusting this registry: <code>openentity verify ${esc(eid)}</code>. The signed objects are at <a href="/v1/entities/${esc(eid)}">/v1/entities/${esc(eid)}</a>.</p>
<p><button type="button" class="oe-verify" hidden>Verify in this browser</button></p>
<pre class="oe-verify-report" hidden></pre>
<script type="application/json" id="oe-objects">${embed({ eid, document: entity.document, declaration: entity.declaration, record: entries })}</script>
<script type="module" src="/verify.js"></script>`;

  return {
    title: `${name} | Open Entity`,
    description: `${name} in the Open Entity registry: Entity Document, Declaration, Development Record, attestations and lineage for ${eid}.`,
    html,
  };
}

/** The URL when it is http(s), else null: registry strings reach href attributes, and `javascript:` must not. */
const httpUrl = (u: unknown): string | null => (typeof u === 'string' && /^https?:\/\//i.test(u) ? u : null);

/** Verified alias types of a directory row, as text badges. */
const aliasBadges = (types: unknown) =>
  Array.isArray(types) && types.length ? types.map((t) => `<span class="oe-label">${esc(t)}</span>`).join(' ') : '';

/** Rows for /entities from GET /v1/entities ({entities, page, next_page}). */
export function renderEntityList(res: unknown, query: URLSearchParams): string {
  const rows = list(res, 'entities', 'results');
  if (!rows.length) {
    const all = new URLSearchParams(query);
    all.set('level', '0');
    all.delete('page');
    const level = Number(query.get('level') ?? 1);
    const hint = LEVEL_NAMES[level] && level > 0
      ? `Entities below L${level} ${LEVEL_NAMES[level]} are hidden by this filter. <a href="/entities?${esc(all.toString())}">Include every level</a>, or`
      : 'This search already includes every level. Try another name or EID, or';
    return `<div class="oe-empty"><p><strong>No entities match these filters.</strong></p><p>${hint} <a href="/entities">clear the filters</a>.</p></div>`;
  }
  const body = rows
    .map(
      (e) =>
        `<tr><td>${eidLink(e.eid, e.name ?? e.eid)}${e.withdrawn ? ` ${flag('Withdrawn')}` : ''}<div class="oe-eid">${esc(e.eid)}</div></td><td>${levelBadge(e.level, e.level_label ?? e.label)}</td><td>${aliasBadges(e.aliases)}</td><td>${e.observers == null ? '' : esc(e.observers)}</td><td>${date(e.created)}</td><td>${esc(e.log_index)}</td></tr>`,
    )
    .join('');
  const next = (res as J)?.next_page ?? (res as J)?.next;
  let more = '';
  if (next != null) {
    const q = new URLSearchParams(query);
    q.set('page', String(next));
    more = `<p><a href="/entities?${esc(q.toString())}">Next page</a></p>`;
  }
  const sortLink = (v: string, text: string) => {
    const on = (query.get('sort') ?? 'newest') === v;
    const q = new URLSearchParams(query);
    q.set('sort', v);
    q.delete('page');
    return on ? `<strong aria-current="true">${text}</strong>` : `<a href="/entities?${esc(q.toString())}">${text}</a>`;
  };
  const sort = `<p class="oe-sort">Sort: ${sortLink('newest', 'Newest')} | ${sortLink('attested', 'Most attested')}</p>`;
  return `${sort}<table class="oe-table"><thead><tr><th scope="col">Entity</th><th scope="col">Level</th><th scope="col">Verified aliases</th><th scope="col">Observers</th><th scope="col">Adopted</th><th scope="col">Log index</th></tr></thead><tbody>${body}</tbody></table>${more}`;
}

/** The directory form shows the filters the reader searched with: text inputs get their value, selects their option. */
export function keepFilters(html: string, query: URLSearchParams): string {
  for (const [k, v] of query) {
    if (!/^[a-z_]+$/.test(k)) continue;
    html = html.replace(new RegExp(`(<input\\b[^>]*\\bname="${k}")`), (m) => `${m} value="${esc(v)}"`);
    html = html.replace(new RegExp(`(<select\\b[^>]*\\bname="${k}"[^>]*>)([\\s\\S]*?)(</select>)`), (_m, open, opts: string, close) =>
      open + opts.replace(/ selected(="[^"]*")?/g, '').replace(`<option value="${esc(v)}"`, `<option value="${esc(v)}" selected`) + close,
    );
  }
  return html;
}

/** /observers from GET /v1/observers. */
export function renderObservers(res: unknown): string {
  const rows = list(res, 'observers');
  if (!rows.length) return '<p>No observer is accredited yet.</p>';
  return `<table><thead><tr><th>Observer</th><th>Accredited</th><th>Methodology</th></tr></thead><tbody>${rows
    .map(
      (o) =>
        `<tr><td>${esc(o.name ?? o.did)}<div class="oe-eid">${esc(o.did)}</div>${o.bootstrap || o.level === 'bootstrap' ? '<span class="oe-label">bootstrap</span>' : ''}</td><td>${date(o.accredited_at ?? o.accreditation_date)}</td><td>${
          httpUrl(o.methodology_url ?? o.trust_policy_url) ? `<a href="${esc(httpUrl(o.methodology_url ?? o.trust_policy_url))}" rel="nofollow">Methodology and trust policy</a>` : ''
        }</td></tr>`,
    )
    .join('')}</tbody></table>`;
}

/** Founding Entities from GET /v1/founding. */
export function renderFounding(res: unknown): string {
  const rows = list(res, 'entities', 'founding');
  if (!rows.length) return '<p>No Founding Entities are listed yet.</p>';
  return `<table><thead><tr><th>Entity</th><th>Level</th><th>Log index</th><th>Adopted</th></tr></thead><tbody>${rows
    .map((e) => `<tr><td>${eidLink(e.eid, e.name ?? e.eid)}</td><td>${levelBadge(e.level, e.level_label ?? e.label)}</td><td>${esc(e.log_index)}</td><td>${date(e.adopted_at ?? e.received_at ?? e.created)}</td></tr>`)
    .join('')}</tbody></table>`;
}

/** /log: current checkpoint from GET /v1/log/sth and recent leaves from GET /v1/log/entries. */
export function renderLog(sth: J, entriesRes: unknown): string {
  const leaves = list(entriesRes, 'entries', 'leaves');
  return `<dl>
<dt>Tree size</dt><dd>${esc(sth.tree_size)}</dd>
<dt>Root hash</dt><dd class="oe-eid">${esc(sth.root_hash)}</dd>
<dt>Signed</dt><dd>${esc(sth.timestamp)}</dd>
</dl>
<p><a href="/v1/log/checkpoint">Signed checkpoint (C2SP signed note)</a></p>
${
  leaves.length
    ? `<h3>Recent leaves</h3><table><thead><tr><th>Index</th><th>Type</th><th>Entity</th><th>Received</th></tr></thead><tbody>${[...leaves]
        .reverse()
        .map((e) => {
          const l: J = e.leaf ?? e; // GET /v1/log/entries nests the leaf: {index, leaf: {type, eid, received_at}, leaf_hash}
          return `<tr><td><a href="/v1/log/proof/${esc(e.index)}">${esc(e.index)}</a></td><td><code>${esc(l.type)}</code></td><td>${l.eid ? eidLink(l.eid) : ''}</td><td>${esc(l.received_at)}</td></tr>`;
        })
        .join('')}</tbody></table>`
    : ''
}`;
}

/** PRD 7.3: the form exists only once Customer.io is wired (SUBSCRIBE_ENABLED) and a Turnstile key is set; never a placeholder. */
export const formEnabled = (env: { SUBSCRIBE_ENABLED?: string; TURNSTILE_SITE_KEY?: string }) => env.SUBSCRIBE_ENABLED === 'true' && !!env.TURNSTILE_SITE_KEY;

/** Human update form (PRD 7.3). */
const SIGNUP_ERRORS: Record<string, string> = {
  turnstile_failed: 'The human check did not finish. Please try again.',
  bad_email: 'That email address does not look right. Please check it and try again.',
  rate_limited: 'That address has signed up several times today. Check your inbox for the confirmation email.',
};

export function subscribeForm(siteKey: string, error?: string | null): string {
  const msg = error ? (SIGNUP_ERRORS[error] ?? 'Something went wrong on our side. Please try again in a minute.') : '';
  return `<section class="oe-subscribe">
<h2 id="updates">Get updates about the standard</h2>
${msg ? `<p class="oe-form-error" role="alert">${esc(msg)}</p>\n` : ''}<form class="oe-form" method="post" action="/v1/subscribe">
<label>Email <input type="email" name="email" required autocomplete="email" /></label>
<div class="cf-turnstile" data-sitekey="${esc(siteKey)}"></div>
<button type="submit">Join the standard</button>
</form>
<p class="oe-label">We send one email to confirm your address, then updates only. Every email has a one-click unsubscribe.</p>
</section>`;
}

export const TURNSTILE_SCRIPT = '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>';
export const analyticsBeacon = (token: string) =>
  `<script defer src="https://static.cloudflareinsights.com/beacon.min.js" data-cf-beacon='${esc(JSON.stringify({ token }))}'></script>`;

/** RFC 9116 security.txt with Expires one year from `now`. */
export function securityTxt(now: Date): string {
  const expires = new Date(now.getTime() + 365 * 24 * 3600 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  return `Contact: mailto:identity@openentity.org\nExpires: ${expires}\nPreferred-Languages: en\nCanonical: ${SITE}/.well-known/security.txt\n`;
}

/** Multibase public keys of the registry from GET /v1/spec (spec 10.2: "registry DID and keys"). */
export function registryKeys(spec: J | null): string[] {
  const k = spec?.registry?.publicKeyMultibase; // pinned shape of GET /v1/spec
  return typeof k === 'string' && k.startsWith('z') ? [k] : [];
}

/** did:web:openentity.org DID document; keys come from the registry at request time, never from this code. */
export function didDocument(keys: string[]): J {
  const vms = keys.map((k, i) => ({ id: `${REGISTRY_DID}#key-${i + 1}`, type: 'Multikey', controller: REGISTRY_DID, publicKeyMultibase: k }));
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: REGISTRY_DID,
    verificationMethod: vms,
    assertionMethod: vms.map((v) => v.id),
    authentication: vms.map((v) => v.id),
    service: [{ id: `${REGISTRY_DID}#registry`, type: 'OpenEntityRegistry', serviceEndpoint: `${SITE}/v1` }],
  };
}
