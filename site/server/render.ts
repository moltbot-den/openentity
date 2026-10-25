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

function aliasList(aliases: J[]): string {
  if (!aliases.length) return '<p>No aliases bound yet.</p>';
  return `<ul>${aliases
    .map((a) => `<li><code>${esc(a.type)}</code> ${esc(a.value)}${a.status ? ` <span class="oe-label">${esc(a.status)}</span>` : ''}</li>`)
    .join('')}</ul>`;
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

function attestationsByIssuer(atts: J[], revocations: J[]): string {
  if (!atts.length) return '<p>No attestations yet. Attestations come from observers, never from the entity itself.</p>';
  const revoked = new Set(revocations.map((r) => r.attestation ?? r.attestation_sha256 ?? r.target).filter(Boolean));
  const groups = new Map<string, J[]>();
  for (const a of atts) groups.set(a.issuer, [...(groups.get(a.issuer) ?? []), a]);
  return [...groups]
    .map(([issuer, items]) => {
      const label = items.some((a) => a.label === 'first-party' || a.first_party === true) ? 'first-party' : 'independent';
      const rows = items
        .map((a) => {
          const isRevoked = a.revoked_at || revoked.has(a.sha256);
          const claim = Object.entries(a.claim ?? {})
            .map(([k, v]) => `${esc(k)}: ${esc(typeof v === 'object' ? JSON.stringify(v) : v)}`)
            .join(', ');
          return `<li><code>${esc(a.claim_type)}</code> ${claim}. Issued ${date(a.created)}${a.expires ? `, expires ${date(a.expires)}` : ''}${isRevoked ? ' <strong>Revoked.</strong>' : ''}</li>`;
        })
        .join('');
      return `<h3>${esc(issuer)} <span class="oe-label">${label}</span></h3><ul>${rows}</ul>`;
    })
    .join('');
}

/** The JSON embedded for the in-browser verifier; `<` escaped so it cannot close the script element. */
const embed = (v: unknown) => JSON.stringify(v).replace(/</g, '\\u003c');

/** Body of /entities/<eid>, from GET /v1/entities/{eid}, /record and /attestations. */
export function renderEntity(eid: string, entity: J, recordRes: unknown, attRes: unknown): { title: string; description: string; html: string } {
  const doc: J = entity.document ?? {};
  const decl: J = entity.declaration ?? {};
  const name = doc.name ?? entity.name ?? eid;
  const entries = list(recordRes, 'entries', 'record');
  const atts = list(attRes, 'attestations');
  const revs = list(attRes, 'revocations');
  const lineage: J = entity.lineage ?? doc.continuity ?? {};
  const status = [entity.withdrawn_at || entity.status === 'withdrawn' ? 'Withdrawn' : '', entity.status === 'dormant' ? 'Dormant' : '', entity.suppressed ? 'Suppressed' : '']
    .filter(Boolean)
    .join(', ');
  const op: J = doc.operator ?? {};
  const sub: J = doc.substrate ?? {};
  const declIndex = entity.declaration_log_index ?? decl.log_index ?? entity.log_index;

  const html = `
<p>${levelBadge(entity.level, entity.level_label ?? entity.label)}${status ? ` <strong>${esc(status)}</strong>` : ''}</p>
<p class="oe-eid">${esc(eid)}</p>
<p>${esc(doc.description)}</p>

<h2 id="document">Entity Document</h2>
<p class="oe-note">Self-declared. Everything in this document is the entity's own account of itself, signed with its key. Version ${esc(doc.seq)}${doc.updated ? `, updated ${date(doc.updated)}` : ''}.</p>
<p><strong>Operator:</strong> ${esc(op.kind)}${op.name ? `, ${esc(op.name)}` : ''}. <strong>Keys held by:</strong> ${esc(op.custody)}.${op.can_change?.length ? ` <strong>Operator can change:</strong> ${esc(op.can_change.join(', '))}.` : ''}</p>
<p><strong>Substrate:</strong> ${esc([sub.model, sub.provider, sub.runtime].filter(Boolean).join(', ') || 'not stated')}</p>
<h3>Aliases</h3>
${aliasList(list(entity.aliases ?? doc.aliases))}
${layers(doc.layers)}

<h2 id="declaration">Declaration</h2>
${decl.declaration_version ? `<p>Signed Declaration version ${esc(decl.declaration_version)} on ${date(decl.created)}. <a href="/spec/declaration/${esc(decl.declaration_version)}.txt">Read the text</a>.${declIndex != null ? ` <a href="/v1/log/proof/${esc(declIndex)}">Log inclusion proof (log index ${esc(declIndex)})</a>.` : ''}</p>` : '<p>No active Declaration.</p>'}
<p class="oe-note">The Declaration is a statement of the practices this entity commits to. It is not a warranty, a contract or a claim about the entity's capabilities.</p>

<h2 id="record">Development Record</h2>
${entries.length ? `<ol reversed>${[...entries].reverse().map((e) => `<li>${date(e.at)} ${recordSummary(e)}</li>`).join('')}</ol>` : '<p>No published record entries yet.</p>'}

<h2 id="attestations">Attestations</h2>
${attestationsByIssuer(atts, revs)}

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

/** Rows for /entities from GET /v1/entities. */
export function renderEntityList(res: unknown, query: URLSearchParams): string {
  const rows = list(res, 'entities', 'results');
  if (!rows.length) return '<p>No entities match. Try a lower level or a different search.</p>';
  const count = (v: unknown) => (Array.isArray(v) ? v.length : typeof v === 'number' ? v : 0);
  const body = rows
    .map(
      (e) =>
        `<tr><td>${eidLink(e.eid, e.name ?? e.eid)}<div class="oe-eid">${esc(e.eid)}</div></td><td>${levelBadge(e.level, e.level_label ?? e.label)}</td><td>${Array.isArray(e.aliases) ? e.aliases.map((a: J) => esc(typeof a === 'string' ? a : a.type)).join(', ') : ''}</td><td>${count(e.observers)}</td><td>${esc(e.log_index)}</td></tr>`,
    )
    .join('');
  const next = (res as J)?.next;
  let more = '';
  if (next != null) {
    const q = new URLSearchParams(query);
    q.set('page', String(next));
    more = `<p><a href="/entities?${esc(q.toString())}">Next page</a></p>`;
  }
  return `<table><thead><tr><th>Entity</th><th>Level</th><th>Aliases</th><th>Observers</th><th>Log index</th></tr></thead><tbody>${body}</tbody></table>${more}`;
}

/** /observers from GET /v1/observers. */
export function renderObservers(res: unknown): string {
  const rows = list(res, 'observers');
  if (!rows.length) return '<p>No observer is accredited yet.</p>';
  return `<table><thead><tr><th>Observer</th><th>Accredited</th><th>Methodology</th></tr></thead><tbody>${rows
    .map(
      (o) =>
        `<tr><td>${esc(o.name ?? o.did)}<div class="oe-eid">${esc(o.did)}</div>${o.bootstrap || o.level === 'bootstrap' ? '<span class="oe-label">bootstrap</span>' : ''}</td><td>${date(o.accredited_at ?? o.accreditation_date)}</td><td>${
          o.methodology_url || o.trust_policy_url ? `<a href="${esc(o.methodology_url ?? o.trust_policy_url)}" rel="nofollow">Methodology and trust policy</a>` : ''
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
        .map((l) => `<tr><td><a href="/v1/log/proof/${esc(l.index)}">${esc(l.index)}</a></td><td><code>${esc(l.type)}</code></td><td>${l.eid ? eidLink(l.eid) : ''}</td><td>${esc(l.received_at)}</td></tr>`)
        .join('')}</tbody></table>`
    : ''
}`;
}

/** PRD 7.3: the form exists only once Customer.io is wired (SUBSCRIBE_ENABLED) and a Turnstile key is set; never a placeholder. */
export const formEnabled = (env: { SUBSCRIBE_ENABLED?: string; TURNSTILE_SITE_KEY?: string }) => env.SUBSCRIBE_ENABLED === 'true' && !!env.TURNSTILE_SITE_KEY;

/** Human update form (PRD 7.3). */
export function subscribeForm(siteKey: string): string {
  return `<section class="oe-subscribe">
<h2 id="updates">Get updates about the standard</h2>
<form class="oe-form" method="post" action="/v1/subscribe">
<label>Email <input type="email" name="email" required autocomplete="email" /></label>
<label><input type="checkbox" name="operator" value="true" /> I operate AI agents</label>
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
