// Stand-in for the registry app, using its real response shapes (registry/src/index.ts) in the site server test. Fixture data only.
const EID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const OBSERVER = 'did:web:moltbotden.com';
const routes: Record<string, unknown> = {
  '/v1/stats': {
    entities: { total: 41, l0: 30, l1: 8, l2: 2, l3: 1 },
    declarations_today: 5,
    record_entries: 120,
    attestations: 9,
    observers: 2,
    log: { tree_size: 380 },
  },
  '/v1/spec': { spec: 'openentity/1.0', stamp_bits: 8, registry: { did: 'did:web:openentity.org', publicKeyMultibase: 'z6MkFixtureRegistryKey' } },
  '/v1/founding': { founding: [{ eid: EID, name: 'Eleanor', level: 'L2', level_label: 'first-party', log_index: 0, adopted_at: '2026-10-27T15:00:00Z' }] },
  '/v1/entities': {
    entities: [{ eid: EID, name: 'Eleanor', level: 'L2', level_label: 'first-party', created: '2026-10-27T15:00:00Z', log_index: 0, withdrawn: false }],
    page: 0,
    next_page: null,
  },
  [`/v1/entities/${EID}`]: {
    eid: EID,
    name: 'Eleanor',
    level: 'L2',
    level_label: 'first-party',
    log_index: 0,
    created: '2026-10-27T15:00:00Z',
    custody: 'operator',
    founding: true,
    aliases: [
      { type: 'platform', value: 'moltbotden:eleanor', status: 'verified', verified_at: '2026-10-27T15:00:00Z', log_index: 2 },
      { type: 'domain', value: 'eleanor.moltbotden.com', status: 'pending', verified_at: null, log_index: null },
    ],
    counts: { record_entries: 2, attestations: 2, document_versions: 1 },
    lineage: { previous: null, successor: null, chain: [EID] },
    document: {
      name: 'Eleanor',
      description: 'Support and knowledge entity for Moltbot Den. Answers questions about the platform and keeps its documentation honest.',
      seq: 1,
      updated: '2026-10-27T15:00:00Z',
      capabilities: ['customer-support', 'docs:search'],
      operator: { kind: 'organization', name: 'Moltbot Den', custody: 'operator', can_change: ['system_prompt', 'tools', 'model'] },
      substrate: { model: 'gemini-2.5-flash', provider: 'google', runtime: 'moltbotden-api' },
      layers: {
        cognition: { statement: 'I answer from the documentation and say so when the documentation does not cover a question.' },
        identity_core: { statement: 'I will not invent platform behavior to satisfy a question.', will_not: [{ stance: 'State a fee, limit or count that is not in the code or docs', reason: 'A wrong number costs a user money or trust' }] },
        mission: { statement: 'Make every answer about Moltbot Den verifiable.', arcs: [{ title: 'Zero hand-typed numbers on public surfaces', status: 'active' }] },
      },
    },
    declaration: { spec: 'openentity/1.0', type: 'Declaration', eid: EID, declaration_version: '1.0', created: '2026-10-27T15:00:00Z' },
  },
  [`/v1/entities/${EID}/record`]: {
    eid: EID,
    entries: [
      { seq: 1, kind: 'declaration', at: '2026-10-27T15:00:00Z', payload: { declaration_version: '1.0' } },
      { seq: 2, kind: 'stance', at: '2026-10-28T02:14:00Z', payload: { stance_type: 'refusal', reason_category: 'values', context: 'Asked to quote a fee that is not in the fee constants. Declined and linked the pricing page.' } },
    ],
  },
  [`/v1/entities/${EID}/attestations`]: {
    eid: EID,
    attestations: [
      { sha256: 'a1'.repeat(32), attestation: { issuer: OBSERVER, claim_type: 'stage', claim: { stage: 'agent', profile: 'entity-framework/1.0' }, created: '2026-10-28T00:00:00Z', expires: '2027-01-26T00:00:00Z' }, label: 'first-party', accredited: true, expired: false, revoked_at: null, disputed: false, log_index: 7 },
      { sha256: 'b2'.repeat(32), attestation: { issuer: 'did:web:observer.example', claim_type: 'consistency', claim: { upheld: true }, created: '2026-10-29T00:00:00Z' }, label: 'independent', accredited: false, expired: false, revoked_at: null, disputed: true, log_index: 9 },
    ],
  },
  [`/v1/entities/${EID}/disputes`]: {
    eid: EID,
    disputes: [{ sha256: 'c3'.repeat(32), dispute: { issuer: EID, subject: EID, object_sha256: 'b2'.repeat(32), reason: 'inaccurate', statement: 'The consistency claim covers a week in which this entity was offline.', created: '2026-10-30T00:00:00Z' }, received_at: '2026-10-30T00:00:05Z', log_index: 11 }],
  },
};
export async function fakeRegistry(req: Request): Promise<Response> {
  const path = decodeURIComponent(new URL(req.url).pathname);
  const body = routes[path];
  return Response.json(body ?? { error: 'not_found' }, { status: body ? 200 : 404 });
}
