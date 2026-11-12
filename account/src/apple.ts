// Sign in with Apple server calls (PLAN 2.3): the authorization code exchange at sign-in yields Apple's refresh token,
// kept sealed under the data key (purpose apple-refresh) so account deletion can revoke it. The client secret is a
// short ES256 JWT signed with the team's Sign in with Apple key (SSM apple_siwa_*).
import { importPKCS8, SignJWT } from "jose";
import type { Deps } from "./app.ts";
import { now } from "./db.ts";
import { fail } from "./http.ts";
import type { Purpose } from "./seal.ts";

export interface AppleSiwa { teamId: string; keyId: string; privateKey: string }
export interface Vault { seal(purpose: Purpose, text: string): Promise<string>; open(purpose: Purpose, sealed: string): Promise<string> }
/** What methods.data keeps for an Apple sign-in. */
export interface AppleData { apple_refresh?: string; apple_client_id?: string; apple_token_at?: number }

const APPLE = "https://appleid.apple.com";

export async function clientSecret(k: AppleSiwa, clientId: string, t = now()): Promise<string> {
  return new SignJWT({}).setProtectedHeader({ alg: "ES256", kid: k.keyId }).setIssuer(k.teamId).setIssuedAt(t).setExpirationTime(t + 300)
    .setAudience(APPLE).setSubject(clientId).sign(await importPKCS8(k.privateKey, "ES256"));
}

async function post(d: Deps, path: string, fields: Record<string, string>): Promise<Response> {
  return (d.fetch ?? fetch)(`${APPLE}${path}`, {
    method: "POST", body: new URLSearchParams(fields), redirect: "error", signal: AbortSignal.timeout(5000),
    headers: { "content-type": "application/x-www-form-urlencoded" },
  });
}

/**
 * Exchanges an authorization code (single use, 5 minutes) for Apple's refresh token and returns it sealed. Null when
 * this environment has no Sign in with Apple key yet: sign-in still works, and deletion then has nothing to revoke.
 */
export async function exchangeAppleCode(d: Deps, code: string, clientId: string, redirectUri?: string): Promise<AppleData | null> {
  const k = d.web.apple, v = d.web.vault;
  if (!k || !v) return null;
  const r = await post(d, "/auth/token", {
    client_id: clientId, client_secret: await clientSecret(k, clientId), code, grant_type: "authorization_code", ...(redirectUri ? { redirect_uri: redirectUri } : {}),
  }).catch(() => fail(502, "provider_error", "Apple could not be reached for the code exchange"));
  const j: any = await r.json().catch(() => null);
  if (!r.ok || typeof j?.refresh_token !== "string") fail(502, "provider_error", `Apple's code exchange answered ${r.status} ${j?.error ?? ""}`.trim());
  return { apple_refresh: await v.seal("apple-refresh", j.refresh_token), apple_client_id: clientId, apple_token_at: now() };
}

/** Revokes Apple's refresh token for each Apple sign-in of the account (account deletion). Logged, never thrown. */
export async function revokeAppleTokens(d: Deps, accountId: string): Promise<void> {
  for (const m of await d.db.all<{ id: string; data: string }>("SELECT id, data FROM methods WHERE account_id = $1 AND type = 'apple'", [accountId])) {
    const data: AppleData = JSON.parse(m.data || "{}");
    if (!data.apple_refresh || !data.apple_client_id) continue;
    try {
      if (!d.web.apple || !d.web.vault) throw new Error("no Sign in with Apple key in this environment");
      const r = await post(d, "/auth/revoke", {
        client_id: data.apple_client_id, client_secret: await clientSecret(d.web.apple, data.apple_client_id),
        token: await d.web.vault.open("apple-refresh", data.apple_refresh), token_type_hint: "refresh_token",
      });
      if (!r.ok) throw new Error(`Apple answered ${r.status}`);
    } catch (e) {
      console.error(`Apple token revocation for method ${m.id} failed: ${(e as Error).message}`);
    }
  }
}
