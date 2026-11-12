// Sign-in methods and the account email (PLAN 2.3, 2.4; openapi /v1/account/methods, /v1/account/email). Adding or
// removing a method and changing the email are step-up actions: the session alone never does them. Accounts never
// merge: a method already linked to any account is 409 method_exists.
import type { Context, Hono } from "hono";
import type { Deps } from "./app.ts";
import { newId, now } from "./db.ts";
import { verifyEmailCode } from "./email.ts";
import { bearer, fail, json, str } from "./http.ts";
import { verifyApple, verifyGoogle } from "./idtoken.ts";
import { verifyRegistration } from "./passkey.ts";
import { me } from "./sessions.ts";
import { useNonce } from "./signin.ts";
import { requireApproval } from "./stepup.ts";

/** Sign-in methods only: a passkey registered for the key log (an enrollment) is not one until it is added with step-up. */
export async function methodList(d: Deps, accountId: string) {
  const rows = await d.db.all<any>("SELECT id, type, subject, email, data, created_at, last_used_at FROM methods WHERE account_id = $1 ORDER BY created_at", [accountId]);
  return rows.filter((m) => !(m.type === "passkey" && JSON.parse(m.data || "{}").pending)).map((m) => ({
    id: m.id, type: m.type, label: m.type === "email" ? m.subject : m.type === "passkey" ? "Passkey" : m.email ?? m.type,
    created_at: Number(m.created_at), last_used_at: m.last_used_at === null ? null : Number(m.last_used_at),
  }));
}

/** The identity a proof signs in as: a fresh sign-in with the new method, from the caller's own install. */
async function proven(c: Context, d: Deps, owner: { accountId: string; sid: string }, type: string, proof: any) {
  if (!proof || typeof proof !== "object") fail(400, "bad_request", "proof is required");
  const s = await d.db.first<{ platform: string; install_id: string | null }>("SELECT platform, install_id FROM sessions WHERE id = $1", [owner.sid]);
  const client = { platform: s!.platform, install_id: s!.install_id };
  switch (type) {
    case "apple": {
      const nonce = str(proof.nonce, "proof.nonce", 128);
      await useNonce(d, nonce, client);
      const id = await verifyApple(str(proof.identity_token, "proof.identity_token", 8192), { audience: client.platform === "ios" ? d.apple.native : d.apple.web, nonce, keys: d.providerKeys?.apple });
      return { subject: id.sub, email: id.email, data: {} };
    }
    case "google": {
      const nonce = str(proof.nonce, "proof.nonce", 128);
      await useNonce(d, nonce, client);
      const id = await verifyGoogle(str(proof.id_token, "proof.id_token", 8192), { audience: d.google, nonce, keys: d.providerKeys?.google });
      return { subject: id.sub, email: id.email, data: {} };
    }
    case "email": {
      const email = await verifyEmailCode(d.db, { challengeId: str(proof.challenge_id, "proof.challenge_id", 64), code: String(proof.code ?? ""), pepper: d.pepper });
      return { subject: email, email, data: {} };
    }
    case "passkey": {
      const ch = await d.db.first<{ challenge: string; account_id: string | null }>(
        "UPDATE passkey_challenges SET used_at = $2 WHERE id = $1 AND used_at IS NULL AND expires_at > $2 AND mode = 'register' RETURNING challenge, account_id",
        [str(proof.challenge_id, "proof.challenge_id", 64), now()]);
      if (!ch) fail(410, "challenge_expired", "this passkey challenge expired or was used; start again");
      if (ch!.account_id !== owner.accountId) fail(403, "forbidden", "this challenge belongs to another account");
      if (!proof.response || typeof proof.response !== "object") fail(400, "bad_request", "proof.response is required");
      const r = await verifyRegistration(d.rp, proof.response, ch!.challenge);
      return {
        subject: r.credential.id, email: null,
        data: { public_key: Buffer.from(r.credential.publicKey).toString("base64url"), counter: r.credential.counter, transports: r.credential.transports ?? [], aaguid: r.aaguid, backed_up: r.backedUp, jwk: r.jwk, key_id: r.keyId },
      };
    }
    default:
      return fail(400, "bad_request", "type must be apple, google, passkey or email");
  }
}

export function routes(app: Hono, d: Deps) {
  app.get("/v1/account/methods", async (c) => c.json({ methods: await methodList(d, (await bearer(c, d)).accountId) }));

  app.post("/v1/account/methods", async (c) => {
    const owner = await bearer(c, d);
    const b = await json(c);
    const id = await proven(c, d, owner, b.type, b.proof);
    if (await d.db.first("SELECT 1 FROM methods WHERE type = $1 AND subject = $2", [b.type, id.subject])) fail(409, "method_exists", "this sign-in is already linked to an OpenEntity account");
    await requireApproval(c, d, { accountId: owner.accountId, ownerDid: owner.ownerDid, action: "method.add", params: { type: b.type, subject: id.subject } });
    const t = now(), methodId = newId("mth");
    await d.db.run("INSERT INTO methods (id, account_id, type, subject, email, data, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
      [methodId, owner.accountId, b.type, id.subject, id.email, JSON.stringify(id.data), t]);
    return c.json((await methodList(d, owner.accountId)).find((m) => m.id === methodId), 201);
  });

  app.delete("/v1/account/methods/:id", async (c) => {
    const owner = await bearer(c, d);
    const methodId = c.req.param("id");
    const list = await methodList(d, owner.accountId);
    if (!list.some((m) => m.id === methodId)) fail(404, "not_found", "no such sign-in method");
    if (list.length === 1) fail(409, "last_method", "this is the account's only sign-in method; add another first");
    await requireApproval(c, d, { accountId: owner.accountId, ownerDid: owner.ownerDid, action: "method.remove", params: { method_id: methodId } });
    await d.db.run("DELETE FROM methods WHERE id = $1 AND account_id = $2", [methodId, owner.accountId]);
    return c.body(null, 204);
  });

  app.put("/v1/account/email", async (c) => {
    const owner = await bearer(c, d);
    const b = await json(c);
    const email = await verifyEmailCode(d.db, { challengeId: str(b.challenge_id, "challenge_id", 64), code: String(b.code ?? ""), pepper: d.pepper });
    await requireApproval(c, d, { accountId: owner.accountId, ownerDid: owner.ownerDid, action: "email.change", params: { email } });
    await d.db.run("UPDATE accounts SET email = $2, email_private = false WHERE id = $1", [owner.accountId, email]);
    return c.json(await me(d, owner.accountId));
  });
}
