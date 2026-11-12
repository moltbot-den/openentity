// Push hub (PLAN 12.1, openapi /v1/notify and /v1/push-tokens). Products notify an owner's devices through here,
// signed with their DID; the service sends its own notices the same way. A push carries ids only: the app fetches the
// item from the product. The visible text is fixed here per sender and type, so nobody can put words on a lock screen,
// and nothing can be approved from a notification.
import { connect, type ClientHttp2Session } from "node:http2";
import type { Hono } from "hono";
import { importPKCS8, SignJWT } from "jose";
import type { Deps } from "./app.ts";
import { PRODUCT_SITES } from "./approve.ts";
import { bump, now } from "./db.ts";
import { bearer, fail, json, str } from "./http.ts";
import { productSigned } from "./rfc9421.ts";
import { emitMetrics } from "./metrics.ts";

/** What products may send. The service's own notices (sender = the service DID) are the other TEXT keys and enrollment.completed. */
export const PUSH_TYPES = ["approval.requested", "approval.resolved", "alert", "refresh"] as const;
const SILENT = new Set(["approval.resolved", "refresh", "enrollment.completed"]);
const TEXT: Record<string, string> = {
  "approval.requested": "Approval requested. Open OpenEntity to review it.",
  alert: "New alert. Open OpenEntity to see it.",
  "enrollment.pending": "A new device asks to become an approver. Open OpenEntity to check its code.",
  "signin.new": "New sign-in to your account. Open OpenEntity to review it.",
  "deletion.requested": "Deletion of your account was requested. Open OpenEntity to review it.",
  "keylog.genesis": "Approvers were set up on your account. Open OpenEntity to review it.",
  "keylog.revoke": "An approver was removed from your account. Open OpenEntity to review it.",
  "keylog.recover": "Approver recovery started on your account. Open OpenEntity to review it.",
  "keylog.replace_root": "Your root passkey is being replaced. Open OpenEntity to review it.",
  "agent.muted": "An agent was muted for sending too many requests. Open OpenEntity to see it.",
};

export interface PushMessage { sender: string; type: string; id: string; agent?: string; collapseKey?: string; ttl?: number }
export type PushTarget = { provider: "apns"; token: string; environment: "sandbox" | "production" } | { provider: "fcm"; token: string };
/** null when delivered; "gone" when the token is dead and must be removed; otherwise the provider's reason. */
export type Sender = (target: PushTarget, m: PushMessage) => Promise<null | "gone" | string>;

/** The custom data of every push (PushPayload): ids only. */
export const pushData = (m: PushMessage) => ({ oe: { product: m.sender, type: m.type, id: m.id, ...(m.agent ? { agent: m.agent } : {}) } });

/** The APNs body: fixed title and text for visible types, content-available for silent ones. */
export function apnsBody(m: PushMessage) {
  if (SILENT.has(m.type)) return { aps: { "content-available": 1 }, ...pushData(m) };
  return {
    aps: {
      alert: { title: PRODUCT_SITES[m.sender]?.name ?? "OpenEntity", body: TEXT[m.type] ?? "Open OpenEntity to see what changed." },
      sound: "default",
      "interruption-level": m.type === "approval.requested" ? "time-sensitive" : "active",
      "thread-id": m.sender,
    },
    ...pushData(m),
  };
}

export interface ApnsConfig {
  /** The team's APNs auth key (.p8, PKCS#8 PEM), its key id and team id; the topic is the app's bundle id. */
  keyPem: string; keyId: string; teamId: string; topic: string;
  /** Tests only: base URLs instead of Apple's. */
  hosts?: Record<"sandbox" | "production", string>;
}
const APPLE = { production: "https://api.push.apple.com", sandbox: "https://api.sandbox.push.apple.com" };
const DEAD = new Set(["BadDeviceToken", "Unregistered", "DeviceTokenNotForTopic"]);

/** APNs over HTTP/2 with a token-based provider JWT (ES256), reused for 40 minutes (Apple allows up to 60). */
export function apnsSender(cfg: ApnsConfig): Sender {
  const key = importPKCS8(cfg.keyPem, "ES256");
  let jwt: { value: string; at: number } | undefined;
  const sessions = new Map<string, ClientHttp2Session>();
  const session = (base: string) => {
    let s = sessions.get(base);
    if (!s || s.closed || s.destroyed) {
      s = connect(base);
      s.on("error", () => sessions.delete(base));
      s.on("goaway", () => sessions.delete(base));
      sessions.set(base, s);
    }
    return s;
  };
  return async (t, m) => {
    if (t.provider !== "apns") return "not_apns";
    if (!jwt || Date.now() - jwt.at > 40 * 60_000) {
      const iat = Math.floor(Date.now() / 1000);
      jwt = { value: await new SignJWT({ iss: cfg.teamId, iat }).setProtectedHeader({ alg: "ES256", kid: cfg.keyId }).sign(await key), at: Date.now() };
    }
    const silent = SILENT.has(m.type);
    const headers: Record<string, string> = {
      ":method": "POST",
      ":path": `/3/device/${encodeURIComponent(t.token)}`,
      authorization: `bearer ${jwt.value}`,
      "apns-topic": cfg.topic,
      "apns-push-type": silent ? "background" : "alert",
      "apns-priority": silent ? "5" : "10",
      "apns-expiration": String(Math.floor(Date.now() / 1000) + (m.ttl ?? 3600)),
      "content-type": "application/json",
    };
    if (m.collapseKey) headers["apns-collapse-id"] = m.collapseKey;
    const body = JSON.stringify(apnsBody(m));
    return new Promise((resolve) => {
      const req = session((cfg.hosts ?? APPLE)[t.environment]).request(headers);
      let status = 0, text = "";
      req.setTimeout(5000, () => { req.close(); resolve("timeout"); });
      req.on("response", (h) => { status = Number(h[":status"]); });
      req.on("data", (chunk) => { text += chunk; });
      req.on("end", () => {
        if (status === 200) return resolve(null);
        let reason = String(status);
        try { reason = JSON.parse(text).reason ?? reason; } catch { /* no JSON body */ }
        resolve(status === 410 || DEAD.has(reason) ? "gone" : reason);
      });
      req.on("error", (e) => resolve(`error: ${e.message}`));
      req.end(body);
    });
  };
}

// ponytail: FCM goes through Workload Identity Federation once the Google project exists (PLAN 4); until then Android
// tokens are stored and skipped. Add the FCM HTTP v1 sender here when `fcm_enabled` turns on.
export const fcmDisabled: Sender = async () => "fcm_disabled";

// ---------------------------------------------------------------- delivery

export const NOTICE_GRACE = 7 * 86_400;

/**
 * Pushes to the account's installs. Products reach installs with a live session only; the service's own notices also
 * reach installs signed out or removed in the last `grace` seconds (PLAN 3.2: revoked approvers are told for 7 days).
 * A dead token is deleted. Returns how many pushes were delivered; never throws.
 */
export async function push(d: Deps, accountId: string, m: PushMessage, o: { grace?: number; except?: string | null } = {}): Promise<number> {
  const cutoff = now() - (o.grace ?? 0);
  const rows = await d.db.all<{ install_id: string; provider: "apns" | "fcm"; token: string; environment: string | null }>(
    `SELECT p.install_id, p.provider, p.token, p.environment FROM push_tokens p
      WHERE p.account_id = $1 AND (p.removed_at IS NULL OR p.removed_at > $2) AND p.install_id IS DISTINCT FROM $3
        AND EXISTS (SELECT 1 FROM sessions s WHERE s.account_id = p.account_id AND s.install_id = p.install_id AND COALESCE(s.revoked_at, s.expires_at) > $2)`,
    [accountId, cutoff, o.except ?? null]);
  let sent = 0;
  await Promise.all(rows.map(async (r) => {
    const target: PushTarget = r.provider === "apns" ? { provider: "apns", token: r.token, environment: r.environment === "sandbox" ? "sandbox" : "production" } : { provider: "fcm", token: r.token };
    const sender = r.provider === "apns" ? d.web.apns : fcmDisabled;
    try {
      const result = sender ? await sender(target, m) : "apns_unconfigured";
      // One data point per delivery attempt; a provider that is not set up yet makes no attempt.
      if (result !== "apns_unconfigured" && result !== "fcm_disabled") emitMetrics(d.stage, { PushSent: result === null ? 1 : 0, PushFailed: result === null ? 0 : 1 });
      if (result === null) sent++;
      else if (result === "gone") await d.db.run("DELETE FROM push_tokens WHERE install_id = $1 AND token = $2", [r.install_id, r.token]);
      else console.warn(`push ${m.type} to ${r.provider} install ${r.install_id}: ${result}`);
    } catch (e) {
      emitMetrics(d.stage, { PushSent: 0, PushFailed: 1 });
      console.warn(`push ${m.type} to install ${r.install_id} failed: ${(e as Error).message}`);
    }
  }));
  return sent;
}

/** A notice for the owner, from the service itself: pushed with ids only, and mailed when `email` is set. */
export interface OwnerNotice {
  /** The push type, e.g. keylog.revoke, keylog.recover, keylog.replace_root, enrollment.pending, agent.muted. */
  type: string;
  /** The id the app fetches (a key log seq, an enrollment id, an agent DID). */
  id: string;
  agent?: string;
  /** Mail the account email too, with this subject and plain text (PLAN 3.2: revoke, recover and replace_root). */
  email?: { subject: string; text: string };
  /** An install that must not get the push (the new install a sign-in notice is about). */
  exceptInstall?: string | null;
}

/**
 * Sends a notice to every install of the account, including installs signed out in the last 7 days (PLAN 3.2: revoked
 * approvers are told for 7 days), and mails the account email when asked. Core calls it; the web lane delivers it.
 * Never throws: a notice that cannot go out is logged.
 */
export async function notifyOwner(d: Deps, accountId: string, n: OwnerNotice): Promise<void> {
  try {
    await push(d, accountId, { sender: `did:web:${d.host}`, type: n.type, id: n.id, agent: n.agent }, { grace: NOTICE_GRACE, except: n.exceptInstall });
    if (n.email) {
      const a = await d.db.first<{ email: string | null }>("SELECT email FROM accounts WHERE id = $1", [accountId]);
      if (a?.email && d.web.sendMail) await d.web.sendMail(a.email, n.email.subject, n.email.text);
    }
  } catch (e) {
    console.error(`notice ${n.type} for ${accountId} failed: ${(e as Error).message}`);
  }
}

// ---------------------------------------------------------------- routes

const ID = /^[A-Za-z0-9:._-]{1,128}$/;
const AGENT_DID = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const NOTIFY_PER_MINUTE = 600;

export function routes(app: Hono, d: Deps) {
  /** The install in the path must be the caller's own (an app session is bound to one install). */
  const ownInstall = async (c: Parameters<typeof bearer>[0]) => {
    const owner = await bearer(c, d);
    const install = c.req.param("install_id") ?? "";
    if (!UUID.test(install)) fail(400, "bad_request", "install_id must be a UUID");
    const s = await d.db.first<{ install_id: string | null }>("SELECT install_id FROM sessions WHERE id = $1", [owner.sid]);
    if (s?.install_id?.toLowerCase() !== install.toLowerCase()) fail(403, "forbidden", "a session registers push tokens for its own install only");
    return { owner, install: s!.install_id! };
  };

  app.put("/v1/push-tokens/:install_id", async (c) => {
    const { owner, install } = await ownInstall(c);
    const b = await json(c);
    if (b.provider !== "apns" && b.provider !== "fcm") fail(400, "bad_request", "provider must be apns or fcm");
    const token = str(b.token, "token", 4096);
    if (b.provider === "apns" && b.environment !== "sandbox" && b.environment !== "production") fail(400, "bad_request", "environment must be sandbox or production for apns");
    const t = now();
    await d.db.run(`INSERT INTO push_tokens (install_id, account_id, provider, token, environment, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $6)
      ON CONFLICT (install_id) DO UPDATE SET account_id = $2, provider = $3, token = $4, environment = $5, updated_at = $6, removed_at = NULL`,
      [install, owner.accountId, b.provider, token, b.provider === "apns" ? b.environment : null, t]);
    return c.body(null, 204);
  });

  app.delete("/v1/push-tokens/:install_id", async (c) => {
    const { owner, install } = await ownInstall(c);
    await d.db.run("UPDATE push_tokens SET removed_at = $3 WHERE install_id = $1 AND account_id = $2 AND removed_at IS NULL", [install, owner.accountId, now()]);
    return c.body(null, 204);
  });

  app.post("/v1/notify", async (c) => {
    const { did: product } = await productSigned(c, d);
    if ((await bump(d.db, `notify:${product}`, String(Math.floor(now() / 60)))) > NOTIFY_PER_MINUTE) {
      fail(429, "rate_limited", `at most ${NOTIFY_PER_MINUTE} notifications a minute per product`, { retry_after: 60 });
    }
    const b = await json(c);
    if (!(PUSH_TYPES as readonly string[]).includes(b.type)) fail(400, "bad_request", `type must be one of: ${PUSH_TYPES.join(", ")}`);
    if (typeof b.id !== "string" || !ID.test(b.id)) fail(400, "bad_request", "id must be 1 to 128 of [A-Za-z0-9:._-]");
    if (b.agent_did !== undefined && (typeof b.agent_did !== "string" || !AGENT_DID.test(b.agent_did))) fail(400, "bad_request", "agent_did must be an Ed25519 did:key");
    if (b.collapse_key !== undefined && (typeof b.collapse_key !== "string" || !b.collapse_key || b.collapse_key.length > 64)) fail(400, "bad_request", "collapse_key is at most 64 characters");
    if (b.ttl !== undefined && !(Number.isSafeInteger(b.ttl) && b.ttl >= 1 && b.ttl <= 86_400)) fail(400, "bad_request", "ttl is 1 to 86400 seconds");
    const owner = await d.db.first<{ id: string }>("SELECT id FROM accounts WHERE owner_did = $1 AND deleted_at IS NULL", [str(b.owner_did, "owner_did", 256)]);
    if (!owner) fail(404, "owner_unknown", "no OpenEntity account has this owner DID");
    await push(d, owner!.id, { sender: product, type: b.type, id: b.id, agent: b.agent_did, collapseKey: b.collapse_key, ttl: b.ttl });
    return c.json({ queued: true }, 202);
  });
}
