// What every module needs to know about an organisation (orgs.ts): the member's role, the quorum devices and the
// org's agents. An org is an owner principal: its DID is did:web:<rp>:o:<id> and its key log is stored like any owner's
// (keylog.ts), so every product that accepts an owner DID already accepts an org's. Roles rank admin > approver > viewer.
import type { Deps } from "./app.ts";
import type { AgentRow } from "./agents.ts";
import { fail } from "./http.ts";
import { keyLogState } from "./keylog.ts";

export type Role = "admin" | "approver" | "viewer";
export const ROLES: Role[] = ["admin", "approver", "viewer"];
const RANK: Record<Role, number> = { viewer: 0, approver: 1, admin: 2 };
export const atLeast = (role: Role, min: Role) => RANK[role] >= RANK[min];

export interface OrgRow { id: string; owner_did: string; name: string; state: "active" | "paused"; quorum_m: number; seq: number; created_by: string; created_at: number }

/** The org and the caller's role in it. A stranger gets 404 (an org's existence is not told), a member below `min` gets 403. */
export async function orgOf(d: Deps, accountId: string, orgId: string, min: Role): Promise<{ org: OrgRow; role: Role }> {
  const r = await d.db.first<OrgRow & { role: Role }>("SELECT o.*, m.role FROM orgs o JOIN org_members m ON m.org_id = o.id WHERE o.id = $1 AND m.account_id = $2", [orgId, accountId]);
  if (!r) fail(404, "not_found", "no such organisation");
  if (!atLeast(r!.role, min)) fail(403, "forbidden_role", `this needs the ${min} role`);
  return { org: { ...r!, quorum_m: Number(r!.quorum_m), seq: Number(r!.seq), created_at: Number(r!.created_at) }, role: r!.role };
}

/**
 * The devices whose approvals count for the org: each admin's and approver's registered device that is still a current
 * approver in the org key log. One device per member, so m devices are m members; a device revoked in the log drops out.
 */
export async function quorumDevices(d: Deps, org: OrgRow): Promise<{ kid: string; account_id: string }[]> {
  const log = await keyLogState(d, org.owner_did);
  if (!log || log.closed) return [];
  const rows = await d.db.all<{ kid: string; account_id: string }>(
    "SELECT v.kid, v.account_id FROM org_devices v JOIN org_members m ON m.org_id = v.org_id AND m.account_id = v.account_id WHERE v.org_id = $1 AND m.role IN ('admin', 'approver') ORDER BY v.kid", [org.id]);
  return rows.filter((r) => log.approvers.some((a) => a.kid === r.kid));
}

/** The policy products read: m of these kids. `satisfiable` is false while fewer than m devices are registered (nothing can pass). */
export async function quorumOf(d: Deps, org: OrgRow) {
  const of = (await quorumDevices(d, org)).map((v) => v.kid);
  return { m: org.quorum_m, of, satisfiable: of.length >= org.quorum_m };
}

/** One of the org's agents (any state but unlinked), or 404. */
export async function orgAgent(d: Deps, org: OrgRow, did: string): Promise<AgentRow> {
  return (await d.db.first<AgentRow>("SELECT * FROM agents WHERE did = $1 AND org_id = $2 AND state <> 'unlinked'", [did, org.id])) ?? fail(404, "not_found", "no such agent in this organisation");
}

export const bumpOrg = (d: Deps, orgId: string) => d.db.run("UPDATE orgs SET seq = seq + 1 WHERE id = $1", [orgId]);

/** The device that signed is the registered device of this member: an org action is the member's own act, not any approver's. */
export async function memberDevice(d: Deps, org: OrgRow, accountId: string, kid: string): Promise<void> {
  if (!(await d.db.first("SELECT 1 FROM org_devices WHERE org_id = $1 AND account_id = $2 AND kid = $3", [org.id, accountId, kid]))) {
    fail(403, "device_not_registered", "sign with your own device for this organisation (PUT /v1/orgs/{id}/device registers it)");
  }
}
