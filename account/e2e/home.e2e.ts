// The home page in a real browser: a web-only owner turns on approvals with a passkey (the page builds and signs the
// genesis entry itself: JCS, SHA-256, base32, WebAuthn), then deletes the account with a passkey step-up. Chrome with a
// CDP virtual authenticator; every request to https://localhost is answered in-process by the account app.
import { randomUUID } from "node:crypto";
import { chromium, type Route } from "playwright-core";
import { afterAll, expect, test } from "vitest";
import { createApp } from "../src/app.ts";
import { keyLogState } from "../src/keylog.ts";
import { rpFor } from "../src/passkey.ts";
import { openSession } from "../src/sessions.ts";
import { testDeps } from "../test/helpers.ts";

const HOST = "localhost";
const d = await testDeps({ host: HOST, rp: rpFor(HOST) });
const app = createApp(d);
const browser = await chromium.launch({ channel: "chrome", headless: true });
afterAll(() => browser.close());

const serve = async (route: Route) => {
  const req = route.request();
  const body = req.postDataBuffer();
  const r = await app.fetch(new Request(req.url(), { method: req.method(), headers: await req.allHeaders(), body: body?.length ? new Uint8Array(body) : undefined }));
  await route.fulfill({ status: r.status, headers: Object.fromEntries(r.headers), body: Buffer.from(await r.arrayBuffer()) });
};

test("a web-only owner turns on approvals with a passkey, then deletes the account with a passkey step-up", async () => {
  const accountId = `acct_${randomUUID().replace(/-/g, "").slice(0, 26)}`;
  await d.db.run("INSERT INTO accounts (id, email, app_account_token, created_at) VALUES ($1, 'webonly@example.com', $2, $3)", [accountId, randomUUID(), Math.floor(Date.now() / 1000)]);
  await d.db.run("INSERT INTO methods (id, account_id, type, subject, email, created_at) VALUES ('mth_webonly', $1, 'email', 'webonly@example.com', 'webonly@example.com', 1)", [accountId]);
  const s = await openSession(d.db, { accountId, platform: "web", amr: "email" });

  const context = await browser.newContext();
  await context.route("https://localhost/**", serve);
  await context.addCookies([{ name: "__Host-oe_session", value: s.refreshToken, url: "https://localhost/", secure: true, httpOnly: true, sameSite: "Strict" }]);
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("dialog", (dlg) => dlg.accept());

  await page.goto("https://localhost/");
  await page.locator("#approvals-off:not([hidden])").waitFor();
  expect(await page.locator("#who").textContent()).toBe("webonly@example.com");
  await page.click("#turn-on");
  await page.locator("#approvals-on:not([hidden])").waitFor();
  expect(errors).toEqual([]);
  const ownerDid = (await d.db.first<{ owner_did: string }>("SELECT owner_did FROM accounts WHERE id = $1", [accountId]))!.owner_did;
  const log = (await keyLogState(d, ownerDid))!;
  expect(log.approvers.map((c) => c.type)).toEqual(["webauthn"]); // the root passkey alone: it approves
  expect(await page.locator("#approvers li").count()).toBe(1);

  await page.click("#delete");
  await page.waitForURL("https://localhost/");
  await page.locator("#signin:not([hidden])").waitFor();
  expect(errors).toEqual([]);
  expect((await d.db.first<{ deleted_at: number | null }>("SELECT deleted_at FROM accounts WHERE id = $1", [accountId]))!.deleted_at).not.toBeNull();
  expect((await keyLogState(d, ownerDid))!.closed).toBe(true);
  await context.close();
});
