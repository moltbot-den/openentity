// Stand-in for the registry app, using its real response shapes (registry/src/index.ts) in the site server test. Fixture data only.
const EID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const routes: Record<string, unknown> = {
  '/v1/stats': { entities: { total: 41, l0: 30, l1: 8, l2: 2, l3: 1 }, declarations_today: 5, observers: 2 },
  '/v1/spec': { spec: 'openentity/1.0', stamp_bits: 8, registry: { did: 'did:web:openentity.org', publicKeyMultibase: 'z6MkFixtureRegistryKey' } },
  '/v1/founding': { founding: [{ eid: EID, name: 'Eleanor', level: 'L2', level_label: 'first-party', log_index: 0, adopted_at: '2026-10-27T15:00:00Z' }] },
  [`/v1/entities/${EID}`]: {
    eid: EID,
    level: 'L2',
    level_label: 'first-party',
    document: { name: 'Eleanor', description: 'Support entity.', seq: 1, operator: { kind: 'organization', name: 'Moltbot Den', custody: 'operator' }, layers: {} },
    declaration: { declaration_version: '1.0', created: '2026-10-27T15:00:00Z', log_index: 0 },
  },
};
export async function fakeRegistry(req: Request): Promise<Response> {
  const path = decodeURIComponent(new URL(req.url).pathname);
  const body = routes[path];
  return Response.json(body ?? { error: 'not_found' }, { status: body ? 200 : 404 });
}

