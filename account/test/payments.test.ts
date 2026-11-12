import { execFileSync } from "node:child_process";
import { createPrivateKey, randomUUID, sign, X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterAll, describe, expect, test } from "vitest";
import { LEDGER } from "../payments/ledger.ts";
import { allocation, CATALOG, verifyAppleJws, type PlayApi } from "../src/store.ts";
import { bearer, call, owner, webApp, type Owner } from "./owner.ts";

// A throwaway App Store chain made per run with openssl: root, intermediate with Apple's WWDR OID, leaf with Apple's
// receipt-signing OID. Nothing here is Apple's key; the real Apple chain is checked separately below.
const dir = mkdtempSync(join(tmpdir(), "oe-store-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));
const ossl = (...a: string[]) => execFileSync("openssl", a, { cwd: dir, stdio: "pipe" });
const ext = (name: string, text: string) => (writeFileSync(join(dir, name), text), name);
for (const k of ["root", "mid", "leaf"]) ossl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", `${k}.key`);
ossl("req", "-x509", "-new", "-key", "root.key", "-subj", "/CN=Test Root", "-days", "2", "-out", "root.pem", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign");
for (const [k, ca, cn, more] of [["mid", "root", "Test WWDR", "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n1.2.840.113635.100.6.2.1=DER:0500\n"], ["leaf", "mid", "Test Receipt Signing", "1.2.840.113635.100.6.11.1=DER:0500\n"]]) {
  ossl("req", "-new", "-key", `${k}.key`, "-subj", `/CN=${cn}`, "-out", `${k}.csr`);
  ossl("x509", "-req", "-in", `${k}.csr`, "-CA", `${ca}.pem`, "-CAkey", `${ca}.key`, "-CAcreateserial", "-days", "2", "-out", `${k}.pem`, "-extfile", ext(`${k}.ext`, more));
}
const pem = (k: string) => readFileSync(join(dir, `${k}.pem`), "utf8");
const der = (k: string) => new X509Certificate(pem(k)).raw.toString("base64");
const testRoot = new X509Certificate(pem("root"));
const leafKey = createPrivateKey(readFileSync(join(dir, "leaf.key")));
const appleJws = (payload: object, chain = [der("leaf"), der("mid"), der("root")]) => {
  const h = Buffer.from(JSON.stringify({ alg: "ES256", x5c: chain })).toString("base64url"), p = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${h}.${p}.${sign("sha256", Buffer.from(`${h}.${p}`), { key: leafKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
};

// Play: a fake Play Developer API and a throwaway key for the Pub/Sub push token.
const play = new Map<string, any>();
const playApi: PlayApi = { subscription: async (t) => play.get(t) ?? Promise.reject(new Error("404")), product: async (_s, t) => play.get(t) ?? Promise.reject(new Error("404")) };
const pubsub = await generateKeyPair("RS256");
const pubsubKeys = createLocalJWKSet({ keys: [{ ...(await exportJWK(pubsub.publicKey)), kid: "g1", alg: "RS256" }] });
const SA = "play-push@oe.iam.gserviceaccount.com", AUD = "https://staging.account.openentity.org/v1/store/google/notifications";
const pushToken = (claims: object = {}) => new SignJWT({ email: SA, email_verified: true, ...claims }).setProtectedHeader({ alg: "RS256", kid: "g1" })
  .setIssuer("https://accounts.google.com").setAudience(AUD).setIssuedAt().setExpirationTime("5m").sign(pubsub.privateKey);

const { d, app, out } = await webApp({ web: { appleRoots: [testRoot], play: playApi, playPush: { audience: AUD, serviceAccount: SA, keys: pubsubKeys } } });
const granted = (o: Owner) => out.calls.filter((c) => c.url.endsWith("/v1/oe/events") && c.body.type === "plan.changed" && c.body.data.owner_did === o.ownerDid).map((c) => ({ host: new URL(c.url).host, ...c.body.data }));
const tokenOf = async (o: Owner) => (await d.db.first<any>("SELECT app_account_token FROM accounts WHERE id = $1", [o.accountId])).app_account_token as string;

const ms = (s: number) => s * 1000, nowS = () => Math.floor(Date.now() / 1000);
const txn = async (o: Owner, sku: string, extra: object = {}) => ({
  transactionId: randomUUID(), originalTransactionId: `orig-${sku}-${o.accountId}`, productId: sku, bundleId: "org.openentity.app", appAccountToken: await tokenOf(o),
  environment: "Sandbox", type: CATALOG[sku].kind === "subscription" ? "Auto-Renewable Subscription" : "Consumable", signedDate: Date.now(), purchaseDate: Date.now(),
  ...(CATALOG[sku].kind === "subscription" ? { expiresDate: ms(nowS() + 30 * 86_400) } : {}), price: 9990, currency: "USD", ...extra,
});
const notify = (notificationType: string, t: object, subtype?: string) => call(app, "POST", "/v1/store/apple/notifications", {
  signedPayload: appleJws({ notificationType, subtype, notificationUUID: randomUUID(), version: "2.0", signedDate: Date.now(), data: { bundleId: "org.openentity.app", environment: "Sandbox", signedTransactionInfo: appleJws(t) } }),
});
const playPush = async (n: object) => call(app, "POST", "/v1/store/google/notifications",
  { subscription: "projects/p/subscriptions/s", message: { messageId: randomUUID(), publishTime: new Date().toISOString(), data: Buffer.from(JSON.stringify({ version: "1.0", packageName: "org.openentity.app", eventTimeMillis: String(Date.now()), ...n })).toString("base64") } },
  { authorization: `Bearer ${await pushToken()}` });

// What each product's plan.changed handler grants (their code, as of this commit):
// Secure My Agent apps/api/src/account-events.ts (pro, team); Agent Secret Store backend/app/api/oe.py GRANTABLE (solo, team);
// ClawGRC apps/agent-protocol/app/services/oe_plan.py (starter|growth|scale); Moltbot Den routers/oe_account.py (den_pro, credits_N).
const ACCEPTS: Record<string, RegExp> = {
  "did:web:securemyagent.ai": /^(pro|team)$/, "did:web:api.agentsecretstore.com": /^(solo|team)$/,
  "did:web:api.clawgrc.com": /(starter|growth|scale)/, "did:web:moltbotden.com": /^(den_pro|credits_500|credits_2200|credits_6000)$/,
};
const API: Record<string, string> = { "did:web:securemyagent.ai": "api.securemyagent.ai", "did:web:api.agentsecretstore.com": "api.agentsecretstore.com", "did:web:api.clawgrc.com": "api.clawgrc.com", "did:web:moltbotden.com": "api.moltbotden.com" };

/** The checks the ledger names. Each buys every covered product and asserts the product was told to grant it. */
const CHECKS: Record<string, (covers: string[]) => Promise<void>> = {
  grant_iap: async (covers) => {
    for (const sku of covers.map((c) => c.slice("iap:".length))) {
      const o = await owner(d), t = await txn(o, sku);
      expect((await notify(CATALOG[sku].kind === "subscription" ? "SUBSCRIBED" : "ONE_TIME_CHARGE", t)).status).toBe(200);
      const [g] = granted(o);
      expect(g, sku).toMatchObject({ host: API[CATALOG[sku].product], product: CATALOG[sku].product, plan: CATALOG[sku].plan, status: "active", source: "iap" });
      expect(g.plan).toMatch(ACCEPTS[g.product]);
      expect(g.store_transaction_id).toBe(CATALOG[sku].kind === "subscription" ? t.originalTransactionId : t.transactionId);
      expect(g.period_end).toBe(CATALOG[sku].kind === "subscription" ? nowS() + 30 * 86_400 : null);
    }
  },
  grant_play: async (covers) => {
    for (const sku of covers.map((c) => c.slice("play:".length))) {
      const o = await owner(d), token = `pt-${randomUUID()}`, sub = CATALOG[sku].kind === "subscription";
      play.set(token, sub
        ? { subscriptionState: "SUBSCRIPTION_STATE_ACTIVE", lineItems: [{ productId: sku, expiryTime: new Date(ms(nowS() + 30 * 86_400)).toISOString() }], externalAccountIdentifiers: { obfuscatedExternalAccountId: await tokenOf(o) }, testPurchase: {} }
        : { purchaseState: 0, purchaseType: 0, obfuscatedExternalAccountId: await tokenOf(o) });
      expect((await playPush(sub ? { subscriptionNotification: { version: "1.0", notificationType: 4, purchaseToken: token, subscriptionId: sku } } : { oneTimeProductNotification: { version: "1.0", notificationType: 1, purchaseToken: token, sku } })).status).toBe(204);
      const [g] = granted(o);
      expect(g, sku).toMatchObject({ host: API[CATALOG[sku].product], plan: CATALOG[sku].plan, status: "active", source: "play", store_transaction_id: token });
      expect(g.plan).toMatch(ACCEPTS[g.product]);
    }
  },
  allocation: async () => {
    const share = async (product: string) => (await allocation(d, 0, nowS() + 60)).find((r) => r.product === product && r.currency === "EUR")?.amount ?? 0;
    const [sma, den] = [await share("did:web:securemyagent.ai"), await share("did:web:moltbotden.com")];
    const a = await owner(d), b = await owner(d);
    await notify("SUBSCRIBED", await txn(a, "org.openentity.app.sma.pro.monthly", { price: 8990, currency: "EUR" }));
    await notify("ONE_TIME_CHARGE", await txn(b, "org.openentity.app.credits.500", { price: 4990, currency: "EUR" }));
    await notify("REFUND", await txn(b, "org.openentity.app.credits.2200", { price: 19_990, currency: "EUR", revocationDate: Date.now() })); // refunded: no share
    expect((await share("did:web:securemyagent.ai")) - sma).toBeCloseTo(8.99);
    expect((await share("did:web:moltbotden.com")) - den).toBeCloseTo(4.99);
  },
  refund: async () => {
    const o = await owner(d), t = await txn(o, "org.openentity.app.ass.team.yearly");
    await notify("SUBSCRIBED", t);
    await notify("REFUND", { ...t, revocationDate: Date.now(), revocationReason: 0, signedDate: Date.now() + 1000 });
    expect(granted(o).map((g) => g.status)).toEqual(["active", "refunded"]);
    const p = await owner(d), token = `pt-${randomUUID()}`;
    play.set(token, { purchaseState: 1, purchaseType: 0, obfuscatedExternalAccountId: await tokenOf(p) });
    await playPush({ oneTimeProductNotification: { version: "1.0", notificationType: 2, purchaseToken: token, sku: "org.openentity.app.credits.2200" } });
    expect(granted(p).map((g) => g.status)).toEqual(["refunded"]);
  },
};

describe("payments ledger (PLAN 10.6): every paid call site has a row and a check", () => {
  test("the gate: every store product on both stores and every paid function is covered; ids are unique; every row has a check", () => {
    const paid = new Set([...Object.keys(CATALOG).flatMap((s) => [`iap:${s}`, `play:${s}`]), "store.ts:allocation", "store.ts:refund"]);
    const covered = new Set(LEDGER.flatMap((r) => r.covers));
    expect([...paid].filter((k) => !covered.has(k)), "not in account/payments/ledger.ts").toEqual([]);
    expect([...covered].filter((k) => !paid.has(k)), "ledger covers something that is not sold").toEqual([]);
    expect(new Set(LEDGER.map((r) => r.id)).size).toBe(LEDGER.length);
    expect(LEDGER.filter((r) => !r.check || !CHECKS[r.check]).map((r) => r.id), "rows without a check").toEqual([]);
    for (const id of ["sma-pro-iap", "sma-team-iap", "ass-solo-iap", "ass-team-iap", "clawgrc-starter-iap", "sma-pro-play", "clawgrc-starter-play", "store-allocation"]) expect(LEDGER.map((r) => r.id)).toContain(id);
  });
  for (const row of LEDGER) test(`check ${row.id}: ${row.what}`, () => CHECKS[row.check!](row.covers));
});

describe("App Store signed data", () => {
  test("the real Apple chain reaches the pinned Apple Root CA - G3 (only the signature then fails)", () => {
    // Apple's own certificates, from apple/app-store-server-library-node tests/unit-tests/jws_verification.test.ts.
    const real = JSON.parse(readFileSync(new URL("./fixtures/apple-real-chain.json", import.meta.url), "utf8"));
    const forged = appleJws({ bundleId: "org.openentity.app" }, [real.leaf, real.intermediate, real.root]);
    expect(() => verifyAppleJws(forged, { at: new Date("2026-06-01T00:00:00Z") })).toThrow(/bad signature/);
    expect(() => verifyAppleJws(forged, { at: new Date("2028-01-01T00:00:00Z") })).toThrow(/not valid now/);
    expect(() => verifyAppleJws(appleJws({}), {})).toThrow(/does not reach Apple Root CA - G3/); // our test chain is not Apple's
  });
  test("guard: chain, OIDs, alg and signature are all required", () => {
    expect(verifyAppleJws(appleJws({ a: 1 }), { roots: [testRoot] })).toEqual({ a: 1 });
    expect(() => verifyAppleJws(appleJws({ a: 1 }, [der("leaf"), der("leaf"), der("root")]), { roots: [testRoot] })).toThrow();
    expect(() => verifyAppleJws(appleJws({ a: 1 }, [der("mid"), der("mid"), der("root")]), { roots: [testRoot] })).toThrow();
    expect(() => verifyAppleJws(appleJws({ a: 1 }, [der("leaf"), der("mid")]), { roots: [testRoot] })).toThrow(/three-certificate/);
    const [h, p, s] = appleJws({ a: 1 }).split(".");
    expect(() => verifyAppleJws(`${h}.${Buffer.from('{"a":2}').toString("base64url")}.${s}`, { roots: [testRoot] })).toThrow(/bad signature/);
    expect(() => verifyAppleJws(`${Buffer.from(JSON.stringify({ alg: "HS256", x5c: [] })).toString("base64url")}.${p}.${s}`, { roots: [testRoot] })).toThrow(/ES256/);
  });
  test("guard: the notification endpoint refuses unsigned data and other apps; TEST notifications are fine", async () => {
    expect((await call(app, "POST", "/v1/store/apple/notifications", { signedPayload: "a.b.c" })).body.error).toBe("payload_invalid");
    expect((await call(app, "POST", "/v1/store/apple/notifications", { signedPayload: appleJws({ notificationType: "TEST", data: { bundleId: "com.other.app" } }) })).body.error).toBe("payload_invalid");
    expect((await call(app, "POST", "/v1/store/apple/notifications", { signedPayload: appleJws({ notificationType: "TEST", data: { bundleId: "org.openentity.app" } }) })).status).toBe(200);
  });
});

describe("grants", () => {
  test("POST /v1/purchases: the transaction must name the caller's account; the answer lists the entitlements", async () => {
    const o = await owner(d), other = await owner(d);
    const t = await txn(other, "org.openentity.app.sma.team.monthly");
    expect((await call(app, "POST", "/v1/purchases", { platform: "ios", signed_transaction: appleJws(t) }, bearer(o))).body.error).toBe("account_mismatch");
    expect((await call(app, "POST", "/v1/purchases", { platform: "ios", signed_transaction: "x.y.z" }, bearer(o))).body.error).toBe("transaction_invalid");
    const r = await call(app, "POST", "/v1/purchases", { platform: "ios", signed_transaction: appleJws(await txn(o, "org.openentity.app.sma.team.monthly")) }, bearer(o));
    expect(r.body.entitlements).toEqual([{ product: "did:web:securemyagent.ai", plan: "team", status: "active", source: "iap", period_end: nowS() + 30 * 86_400 }]);
    expect((await call(app, "GET", "/v1/entitlements", undefined, bearer(o))).body).toEqual(r.body);
  });

  test("guard: staging grants only sandbox purchases; production only real ones, except the App Review account while review is open", async () => {
    const o = await owner(d);
    await notify("SUBSCRIBED", await txn(o, "org.openentity.app.sma.pro.monthly", { environment: "Production" }));
    expect(granted(o)).toEqual([]);
    const { createApp } = await import("../src/app.ts");
    const review = await owner(d, { email: "review@openentity.org" });
    for (const [open, who, env, expected] of [[false, review, "Sandbox", 0], [true, review, "Sandbox", 1], [true, await owner(d), "Sandbox", 0]] as const) {
      const prod = createApp({ ...d, stage: "production", web: { ...d.web, appReview: { email: "review@openentity.org", code: "12345678", openSince: open ? nowS() : null } } });
      const before = granted(who).length;
      await prod.request("https://staging.account.openentity.org/v1/store/apple/notifications", { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ signedPayload: appleJws({ notificationType: "SUBSCRIBED", data: { bundleId: "org.openentity.app", signedTransactionInfo: appleJws(await txn(who, "org.openentity.app.sma.pro.monthly", { environment: env, originalTransactionId: randomUUID() })) } }) }) });
      expect(granted(who).length - before, `review open ${open}`).toBe(expected);
    }
  });

  test("notifications out of order never move a plan back; a repeat sends nothing new", async () => {
    const o = await owner(d), t = await txn(o, "org.openentity.app.ass.solo.monthly");
    await notify("SUBSCRIBED", { ...t, signedDate: Date.now() });
    await notify("SUBSCRIBED", { ...t, signedDate: Date.now() });
    await notify("EXPIRED", { ...t, expiresDate: Date.now() - 1000, signedDate: Date.now() - 60_000 }); // older than what we hold
    expect(granted(o).map((g) => g.status)).toEqual(["active"]);
    await notify("DID_FAIL_TO_RENEW", { ...t, expiresDate: Date.now() - 1000, signedDate: Date.now() + 5000 }, "GRACE_PERIOD");
    await notify("EXPIRED", { ...t, expiresDate: Date.now() - 1000, signedDate: Date.now() + 10_000 });
    expect(granted(o).map((g) => g.status)).toEqual(["active", "grace", "expired"]);
  });

  test("guard: Play notifications need the push subscription's Google-signed token", async () => {
    const body = { subscription: "s", message: { messageId: "1", publishTime: new Date().toISOString(), data: Buffer.from(JSON.stringify({ packageName: "org.openentity.app", testNotification: { version: "1.0" } })).toString("base64") } };
    expect((await call(app, "POST", "/v1/store/google/notifications", body)).status).toBe(401);
    expect((await call(app, "POST", "/v1/store/google/notifications", body, { authorization: `Bearer ${await pushToken({ email: "someone@else.iam.gserviceaccount.com" })}` })).status).toBe(401);
    expect((await call(app, "POST", "/v1/store/google/notifications", body, { authorization: `Bearer ${await pushToken()}` })).status).toBe(204);
    const off = (await webApp()).app;
    expect((await call(off, "POST", "/v1/store/google/notifications", body, { authorization: `Bearer ${await pushToken()}` })).status).toBe(503);
  });
});
