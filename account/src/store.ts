// Store purchases (PLAN 10.3, 10.6; openapi /v1/purchases, /v1/entitlements, /v1/store/*). App Store Server
// Notifications V2 and StoreKit 2 transactions are JWS signed through Apple's chain, checked here to the pinned Apple
// Root CA - G3. Play purchases are read from the Play Developer API (`d.web.play`, Workload Identity Federation) and
// Play notifications arrive by Pub/Sub push with a Google-signed OIDC token. A grant rests only on Apple's signature or
// Google's answer, never on the client's word, and reaches the product as a signed plan.changed (outbound.ts).
import { X509Certificate, verify } from "node:crypto";
import type { Hono } from "hono";
import { createRemoteJWKSet, errors as joseErrors, jwtVerify } from "jose";
import type { Deps } from "./app.ts";
import { newId, now } from "./db.ts";
import { bearer, fail, json, str } from "./http.ts";
import { callProduct, reaches } from "./outbound.ts";
import { BUNDLE_ID } from "./wellknown.ts";

const SMA = "did:web:securemyagent.ai", ASS = "did:web:api.agentsecretstore.com", CGRC = "did:web:api.clawgrc.com", DEN = "did:web:moltbotden.com";
export type Source = "iap" | "play";
export interface Sku { product: string; plan: string; kind: "subscription" | "consumable"; ledger: string }

/**
 * Every product the app sells, the same id on both stores (PLAN 10.2), and what it grants: `plan` is the string each
 * product's plan.changed handler grants (Secure My Agent pro and team; Agent Secret Store solo and team; ClawGRC
 * starter; Moltbot Den den_pro and credits_N). `ledger` names its rows in payments/ledger.ts (`<ledger>-iap|play`).
 */
export const CATALOG: Record<string, Sku> = {
  "org.openentity.app.sma.pro.monthly": { product: SMA, plan: "pro", kind: "subscription", ledger: "sma-pro" },
  "org.openentity.app.sma.team.monthly": { product: SMA, plan: "team", kind: "subscription", ledger: "sma-team" },
  "org.openentity.app.ass.solo.monthly": { product: ASS, plan: "solo", kind: "subscription", ledger: "ass-solo" },
  "org.openentity.app.ass.solo.yearly": { product: ASS, plan: "solo", kind: "subscription", ledger: "ass-solo" },
  "org.openentity.app.ass.team.monthly": { product: ASS, plan: "team", kind: "subscription", ledger: "ass-team" },
  "org.openentity.app.ass.team.yearly": { product: ASS, plan: "team", kind: "subscription", ledger: "ass-team" },
  "org.openentity.app.clawgrc.starter.monthly": { product: CGRC, plan: "starter", kind: "subscription", ledger: "clawgrc-starter" },
  "org.openentity.app.denpro.monthly": { product: DEN, plan: "den_pro", kind: "subscription", ledger: "den-pro" },
  "org.openentity.app.credits.500": { product: DEN, plan: "credits_500", kind: "consumable", ledger: "credits-500" },
  "org.openentity.app.credits.2200": { product: DEN, plan: "credits_2200", kind: "consumable", ledger: "credits-2200" },
  "org.openentity.app.credits.6000": { product: DEN, plan: "credits_6000", kind: "consumable", ledger: "credits-6000" },
};

// ---------------------------------------------------------------- Apple: signed data to the pinned root

/** Apple Root CA - G3 (https://www.apple.com/certificateauthority/AppleRootCA-G3.cer), SHA-256 63:34:3A:...:91:79. */
export const APPLE_ROOT_G3 = new X509Certificate(Buffer.from(
  "MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtfTjjTuxxEtX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK517IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySrMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvOwgPUnPWTxnS4at+qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkLF1vLUagM6BgD56KyKA==",
  "base64"));
// The extensions Apple's signing certificates carry (DER of the OID): the leaf (receipt signing) and the intermediate (WWDR).
const LEAF_OID = Buffer.from("060a2a864886f76364060b01", "hex"), INTERMEDIATE_OID = Buffer.from("060a2a864886f76364060201", "hex");

const invalid = (why: string): never => fail(401, "payload_invalid", `not signed by the App Store: ${why}`);
const valid = (c: X509Certificate, at: Date) => new Date(c.validFrom) <= at && at <= new Date(c.validTo);

/**
 * Verifies App Store signed data (a notification, transaction or renewal info) and returns its payload: ES256 by the
 * leaf of an x5c chain [leaf, intermediate, root] whose intermediate is signed by a pinned root, with Apple's OIDs, all
 * valid at `at`. `roots` is for tests only.
 */
export function verifyAppleJws(jws: unknown, o: { roots?: X509Certificate[]; at?: Date } = {}): any {
  if (typeof jws !== "string" || jws.length > 65_536) return invalid("not a compact JWS");
  const [h, p, s, extra] = jws.split(".");
  if (!h || !p || !s || extra !== undefined) return invalid("not a compact JWS");
  let header: any, payload: any;
  try {
    header = JSON.parse(Buffer.from(h, "base64url").toString("utf8"));
    payload = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
  } catch { return invalid("not JSON"); }
  if (header?.alg !== "ES256" || !Array.isArray(header.x5c) || header.x5c.length !== 3) return invalid("alg must be ES256 with a three-certificate x5c");
  let leaf: X509Certificate, mid: X509Certificate;
  try {
    [leaf, mid] = header.x5c.slice(0, 2).map((c: string) => new X509Certificate(Buffer.from(c, "base64")));
  } catch { return invalid("x5c has a certificate that does not parse"); }
  const at = o.at ?? new Date();
  const root = (o.roots ?? [APPLE_ROOT_G3]).find((r) => mid!.checkIssued(r) && mid!.verify(r.publicKey) && valid(r, at));
  if (!root) return invalid("the chain does not reach Apple Root CA - G3");
  if (!leaf!.checkIssued(mid!) || !leaf!.verify(mid!.publicKey)) return invalid("the leaf is not issued by the intermediate");
  if (!valid(leaf!, at) || !valid(mid!, at)) return invalid("a certificate is not valid now");
  if (!leaf!.raw.includes(LEAF_OID) || !mid!.raw.includes(INTERMEDIATE_OID)) return invalid("not Apple's App Store signing certificates");
  if (!verify("sha256", Buffer.from(`${h}.${p}`), { key: leaf!.publicKey, dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url"))) return invalid("bad signature");
  if (!payload || typeof payload !== "object") return invalid("payload is not an object");
  return payload;
}

// ---------------------------------------------------------------- grants

/** A store purchase as both stores reduce to it. */
export interface Purchase {
  source: Source; sku: string; accountToken: string | null; storeTransactionId: string; status: "active" | "grace" | "expired" | "revoked" | "refunded";
  periodEnd: number | null; signedAt: number; sandbox: boolean; price: number | null; currency: string | null;
}

/** An App Store transaction (JWSTransactionDecodedPayload) and what its notification says, reduced to a Purchase. */
export function fromApple(t: any, n: { type?: string; subtype?: string; renewal?: any } = {}, at = Date.now()): Purchase {
  const sku = CATALOG[t.productId];
  const sub = sku?.kind === "subscription";
  const status = t.revocationDate ? (n.type === "REVOKE" ? "revoked" : "refunded")
    : n.type === "DID_FAIL_TO_RENEW" && n.subtype === "GRACE_PERIOD" ? "grace"
    : sub && typeof t.expiresDate === "number" && t.expiresDate <= at ? "expired"
    : "active";
  const graceEnd = status === "grace" && typeof n.renewal?.gracePeriodExpiresDate === "number" ? n.renewal.gracePeriodExpiresDate : null;
  return {
    source: "iap", sku: String(t.productId), accountToken: typeof t.appAccountToken === "string" ? t.appAccountToken.toLowerCase() : null,
    storeTransactionId: String(sub ? t.originalTransactionId : t.transactionId), status,
    periodEnd: sub ? Math.floor((graceEnd ?? t.expiresDate ?? 0) / 1000) || null : null,
    signedAt: Math.floor(Number(t.signedDate ?? at) / 1000), sandbox: t.environment !== "Production",
    price: typeof t.price === "number" ? t.price : null, currency: typeof t.currency === "string" ? t.currency : null,
  };
}

/**
 * Records a purchase and tells the product when it changed. Production grants only Production purchases, except the
 * App Review demo account's sandbox purchases while APP_REVIEW_OPEN is on; staging grants only sandbox purchases.
 * Returns false when the purchase grants nothing (unknown product, account, or environment).
 */
export async function grant(d: Deps, p: Purchase, accountId?: string): Promise<boolean> {
  const sku = CATALOG[p.sku];
  if (!sku) return (console.warn(`store: unknown product ${p.sku}`), false);
  const a = await d.db.first<{ id: string; owner_did: string | null; email: string | null }>(
    accountId ? "SELECT id, owner_did, email FROM accounts WHERE id = $1 AND deleted_at IS NULL" : "SELECT id, owner_did, email FROM accounts WHERE app_account_token = $1 AND deleted_at IS NULL",
    [accountId ?? p.accountToken]);
  if (!a) return (console.warn(`store: no account for ${p.source} ${p.storeTransactionId}`), false);
  const review = d.web.appReview?.openSince && a.email === d.web.appReview.email;
  if (d.stage === "production" ? p.sandbox && !review : !p.sandbox) return (console.warn(`store: ${p.sandbox ? "sandbox" : "production"} purchase refused in ${d.stage}`), false);
  // Notifications can arrive out of order: a row only moves forward in time. Each change gets a new plan.changed
  // event id and is pending (delivered_at null) in the same write, so a lost or refused grant is resent (sendGrants).
  const t = now();
  const r = await d.db.first<{ changed: boolean }>(
    `INSERT INTO entitlements (source, store_transaction_id, account_id, product, plan, sku, status, period_end, signed_at, price, currency, created_at, updated_at, event_id, send_attempts, next_send_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12, $13, 0, $12)
     ON CONFLICT (source, store_transaction_id) DO UPDATE SET plan = $5, sku = $6, status = $7, period_end = $8, signed_at = $9, updated_at = $12,
       event_id = $13, delivered_at = NULL, send_attempts = 0, next_send_at = $12
       WHERE entitlements.signed_at <= $9 AND (entitlements.status, entitlements.plan, COALESCE(entitlements.period_end, -1)) IS DISTINCT FROM ($7, $5, COALESCE($8, -1))
     RETURNING true AS changed`,
    [p.source, p.storeTransactionId, a.id, sku.product, sku.plan, p.sku, p.status, p.periodEnd, p.signedAt, p.price, p.currency, t, newId("evt")]);
  if (r) await sendGrants(d, { source: p.source, id: p.storeTransactionId });
  return true;
}

/**
 * Sends pending plan.changed events (a grant's product has not taken its latest state yet), oldest first: one row when
 * `one` names it (right after the grant), else every due row (jobs.ts). A failure, a refusal included, is retried
 * with backoff (1 minute doubling, at most an hour) under the same event id, which products dedupe. An owner with no
 * key log yet has no DID, so its grant waits until it has one; a deleted owner's grant, or one for a product this stage
 * never calls (outbound.ts reaches), is dropped.
 */
export async function sendGrants(d: Deps, one?: { source: string; id: string }): Promise<void> {
  const t = now();
  const rows = await d.db.all<any>(
    `SELECT e.*, a.owner_did, a.deleted_at FROM entitlements e JOIN accounts a ON a.id = e.account_id
      WHERE e.delivered_at IS NULL AND e.event_id IS NOT NULL AND ${one ? "e.source = $1 AND e.store_transaction_id = $2" : "e.next_send_at <= $1"}
      ORDER BY e.next_send_at LIMIT 50`, one ? [one.source, one.id] : [t]);
  for (const g of rows) {
    const done = (at: number | null) => d.db.run(
      "UPDATE entitlements SET delivered_at = $3, send_attempts = send_attempts + 1, next_send_at = $4 WHERE store_transaction_id = $1 AND event_id = $2",
      [g.store_transaction_id, g.event_id, at, at ?? t + Math.min(60 * 2 ** Number(g.send_attempts), 3600)]);
    if (g.deleted_at !== null || !reaches(d, g.product)) { await done(t); continue; } // owner.deleted already told the product
    if (!g.owner_did) { await done(null); continue; }
    const r = await callProduct(d, g.product, "/v1/oe/events", {
      id: g.event_id, type: "plan.changed", created_at: Number(g.updated_at),
      data: { owner_did: g.owner_did, product: g.product, plan: g.plan, status: g.status, source: g.source, period_end: g.period_end === null ? null : Number(g.period_end), store_transaction_id: g.store_transaction_id },
    });
    if (r.status >= 200 && r.status < 300) await done(t);
    else {
      console.warn(`store: ${g.product} did not take plan.changed ${g.event_id} (${r.status}); retrying`);
      await done(null);
    }
  }
}

/** The account's store-bought plans (EntitlementList). */
export async function entitlements(d: Deps, accountId: string) {
  const rows = await d.db.all<any>("SELECT product, plan, status, source, period_end FROM entitlements WHERE account_id = $1 ORDER BY updated_at DESC", [accountId]);
  return { entitlements: rows.map((r) => ({ product: r.product, plan: r.plan, status: r.status, source: r.source, period_end: r.period_end === null ? null : Number(r.period_end) })) };
}

/**
 * Store proceeds per product for the books (PLAN 10.3: payouts land with One Frequency Inc.; ledger row store-allocation):
 * the list price of every granted purchase in [from, to), in the store's currency units, by product and currency.
 * ponytail: list price, before the store's commission and tax; the payout reports give the net when they are needed.
 */
export async function allocation(d: Deps, from: number, to: number) {
  const rows = await d.db.all<{ product: string; currency: string; total: number }>(
    "SELECT product, currency, SUM(price) AS total FROM entitlements WHERE created_at >= $1 AND created_at < $2 AND price IS NOT NULL AND status <> 'refunded' GROUP BY product, currency ORDER BY product, currency",
    [from, to]);
  return rows.map((r) => ({ product: r.product, currency: r.currency, amount: Number(r.total) / 1000 }));
}

// ---------------------------------------------------------------- Play

/** The Play Developer API through Workload Identity Federation; absent until the Google project exists (PLAN 4). */
export interface PlayApi {
  subscription(token: string): Promise<any>;
  product(sku: string, token: string): Promise<any>;
}

/** A Play purchase from the Play Developer API (subscriptionsv2.get or products.get), reduced to a Purchase. */
export function fromPlay(sku: string, token: string, r: any, at = Date.now()): Purchase {
  const sub = CATALOG[sku]?.kind === "subscription";
  // Google answers a subscription by its token alone, so the product it names must be the one claimed (gate M7); a
  // one-time product is asked for by SKU, and an answer naming another product is refused all the same.
  const named = sub ? r?.lineItems?.[0]?.productId : r?.productId ?? sku;
  if (named !== sku) fail(422, "transaction_invalid", "the Play purchase is for another product");
  const end = sub ? Date.parse(r.lineItems?.[0]?.expiryTime ?? "") : NaN;
  const state = String(r.subscriptionState ?? "");
  const status = sub
    ? state === "SUBSCRIPTION_STATE_IN_GRACE_PERIOD" ? "grace"
      : state === "SUBSCRIPTION_STATE_ACTIVE" || (state === "SUBSCRIPTION_STATE_CANCELED" && end > at) ? "active"
      : state === "SUBSCRIPTION_STATE_EXPIRED" || state === "SUBSCRIPTION_STATE_ON_HOLD" || state === "SUBSCRIPTION_STATE_PAUSED" ? "expired" : "revoked"
    : r.purchaseState === 0 ? "active" : "refunded";
  return {
    source: "play", sku, accountToken: String((sub ? r.externalAccountIdentifiers?.obfuscatedExternalAccountId : r.obfuscatedExternalAccountId) ?? "").toLowerCase() || null,
    storeTransactionId: token, status, periodEnd: sub && Number.isFinite(end) ? Math.floor(end / 1000) : null,
    signedAt: Math.floor(at / 1000), sandbox: sub ? !!r.testPurchase : r.purchaseType === 0, price: null, currency: null,
  };
}

const googleJwks = createRemoteJWKSet(new URL("https://www.googleapis.com/oauth2/v3/certs"));

export function routes(app: Hono, d: Deps) {
  /** A purchase that names another account is refused: grants follow appAccountToken / obfuscatedAccountId. */
  const mine = async (accountId: string, p: Purchase) => {
    const a = await d.db.first<{ app_account_token: string }>("SELECT app_account_token FROM accounts WHERE id = $1", [accountId]);
    if (!p.accountToken || p.accountToken !== a?.app_account_token.toLowerCase()) fail(409, "account_mismatch", "this purchase belongs to another account");
  };

  app.post("/v1/purchases", async (c) => {
    const owner = await bearer(c, d);
    const b = await json(c);
    let p: Purchase;
    if (b.platform === "ios") {
      let t;
      try { t = verifyAppleJws(str(b.signed_transaction, "signed_transaction", 65_536), { roots: d.web.appleRoots }); } catch { return fail(422, "transaction_invalid", "the transaction is not signed by the App Store"); }
      if (t.bundleId !== BUNDLE_ID) fail(422, "transaction_invalid", "the transaction is for another app");
      p = fromApple(t);
    } else if (b.platform === "android") {
      const play = d.web.play ?? fail(503, "unavailable", "Google Play purchases are not configured yet");
      const sku = str(b.product_id, "product_id", 128), token = str(b.purchase_token, "purchase_token", 4096);
      if (!CATALOG[sku]) fail(422, "transaction_invalid", "unknown product");
      const r = await (CATALOG[sku].kind === "subscription" ? play.subscription(token) : play.product(sku, token)).catch(() => fail(422, "transaction_invalid", "Google Play does not know this purchase"));
      p = fromPlay(sku, token, r);
    } else {
      return fail(400, "bad_request", "platform must be ios or android");
    }
    await mine(owner.accountId, p);
    await grant(d, p, owner.accountId);
    return c.json(await entitlements(d, owner.accountId));
  });

  app.get("/v1/entitlements", async (c) => c.json(await entitlements(d, (await bearer(c, d)).accountId)));

  // App Store Server Notifications V2. 200 for every verified notification, unknown transactions included.
  app.post("/v1/store/apple/notifications", async (c) => {
    const b = await json(c);
    const n = verifyAppleJws(b.signedPayload, { roots: d.web.appleRoots });
    const data = n.data ?? {};
    if (data.bundleId !== BUNDLE_ID) return invalid("the notification is for another app");
    if (data.signedTransactionInfo) {
      const t = verifyAppleJws(data.signedTransactionInfo, { roots: d.web.appleRoots });
      const renewal = data.signedRenewalInfo ? verifyAppleJws(data.signedRenewalInfo, { roots: d.web.appleRoots }) : undefined;
      if (t.bundleId === BUNDLE_ID) await grant(d, fromApple(t, { type: n.notificationType, subtype: n.subtype, renewal }));
    }
    return c.body(null, 200);
  });

  // Google Play Real-time Developer Notifications by Pub/Sub push: the push subscription's Google-signed OIDC token,
  // then the purchase re-read from the Play Developer API. Until Play is set up the answer is 503, so Pub/Sub retries.
  app.post("/v1/store/google/notifications", async (c) => {
    const push = d.web.playPush ?? fail(503, "unavailable", "Google Play notifications are not configured yet");
    const h = c.req.header("authorization") ?? "";
    try {
      const { payload } = await jwtVerify(h.replace(/^Bearer /, ""), push.keys ?? googleJwks, { issuer: ["https://accounts.google.com", "accounts.google.com"], audience: push.audience, algorithms: ["RS256"] });
      if (payload.email !== push.serviceAccount || payload.email_verified !== true) throw new joseErrors.JWTClaimValidationFailed("wrong service account", payload);
    } catch (e) {
      if (e instanceof joseErrors.JOSEError || e instanceof TypeError) fail(401, "unauthorized", "not the Play notifications push subscription");
      throw e;
    }
    const b = await json(c);
    let n: any;
    try { n = JSON.parse(Buffer.from(String(b.message?.data ?? ""), "base64").toString("utf8")); } catch { fail(400, "bad_request", "message.data is not base64 JSON"); }
    if (n.packageName !== BUNDLE_ID) fail(400, "bad_request", "the notification is for another app");
    if (n.testNotification) return c.body(null, 204);
    const play = d.web.play ?? fail(503, "unavailable", "the Play Developer API is not configured yet");
    const sub = n.subscriptionNotification, one = n.oneTimeProductNotification;
    const sku = String(sub?.subscriptionId ?? one?.sku ?? ""), token = String(sub?.purchaseToken ?? one?.purchaseToken ?? "");
    if (!CATALOG[sku] || !token) return c.body(null, 204);
    const r = await (sub ? play.subscription(token) : play.product(sku, token)).catch(() => fail(503, "unavailable", "the Play Developer API did not answer; Pub/Sub will retry"));
    await grant(d, fromPlay(sku, token, r));
    return c.body(null, 204);
  });
}
