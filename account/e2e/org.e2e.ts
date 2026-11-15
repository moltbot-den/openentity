// The org dashboard in a real browser (C5): a web-only owner turns on approvals, creates an organisation (the page builds
// and signs the org's genesis entry with the passkey), sets a budget, signs a mandate for an org agent with the passkey,
// answers a waiting approval, pauses the whole org and resumes it with the org's step-up. Chrome with a CDP virtual
// authenticator; every request to https://localhost is answered in-process by the account app.
import { randomUUID } from "node:crypto";
import { chromium, type Route } from "playwright-core";
import { generateKeyPair, payloadDigest, verifyMandate } from "@openentity/sdk";
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
  const headers = { ...(await req.allHeaders()), "x-oe-viewer-address": "127.0.0.1" };
  const r = await app.fetch(new Request(req.url(), { method: req.method(), headers, body: body?.length ? new Uint8Array(body) : undefined }));
  await route.fulfill({ status: r.status, headers: Object.fromEntries(r.headers), body: Buffer.from(await r.arrayBuffer()) });
};
const now = () => Math.floor(Date.now() / 1000);

test("an org is created, budgeted, signs a mandate, answers an approval, pauses and resumes from the web", async () => {
  const accountId = `acct_${randomUUID().replace(/-/g, "").slice(0, 26)}`;
  await d.db.run("INSERT INTO accounts (id, email, app_account_token, created_at) VALUES ($1, 'ceo@example.com', $2, $3)", [accountId, randomUUID(), now()]);
  await d.db.run("INSERT INTO methods (id, account_id, type, subject, email, created_at) VALUES ('mth_ceo', $1, 'email', 'ceo@example.com', 'ceo@example.com', 1)", [accountId]);
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
  expect(await page.locator("#org-form").isHidden()).toBe(true);
  expect(await page.locator("#orgs-off:not([hidden])").count()).toBe(1);
  await page.click("#turn-on");
  await page.locator("#approvals-on:not([hidden])").waitFor();

  // Create the organisation: the passkey signs its genesis, and is registered as the org's device.
  await page.fill("#org-name", "Acme Robotics");
  await page.click("#org-form button");
  await page.locator("#org:not([hidden])").waitFor();
  expect(await page.locator("#org-title").textContent()).toBe("Acme Robotics (admin)");
  const org = (await d.db.first<{ id: string; owner_did: string }>("SELECT id, owner_did FROM orgs"))!;
  expect((await keyLogState(d, org.owner_did))!.approvers.map((c) => c.type)).toEqual(["webauthn"]);
  expect(await page.locator("#org-members li").count()).toBe(1);
  expect(await page.locator("#org-members li").textContent()).toContain("device");
  expect(await page.locator("#org-quorum").textContent()).toContain("1 of 1");

  // An agent of the org (the pairing flow itself is covered by test/orgs.test.ts).
  const agent = await generateKeyPair();
  await d.db.run("INSERT INTO agents (did, account_id, owner_did, permissions, state, paired_at, org_id) VALUES ($1, $2, $3, '[\"owner.approval\"]', 'active', $4, $5)", [agent.did, accountId, org.owner_did, now(), org.id]);
  await page.reload();
  await page.locator("#org-agents li").first().waitFor();

  // A budget in dollars, then the passkey signs the mandate for it.
  await page.fill("#budget-tx", "50");
  await page.fill("#budget-max", "200.50");
  await page.click("#budget-form button");
  await page.locator("#org-budgets li").first().waitFor();
  expect(await page.locator("#org-budgets li").textContent()).toContain("$50.00 a purchase, $200.50 per P1D");
  await page.locator("#org-agents li button", { hasText: "Sign a mandate" }).click();
  await page.waitForFunction(() => document.querySelector("#org-error")?.hasAttribute("hidden"));
  await expect.poll(async () => (await d.db.first<{ n: number }>("SELECT count(*)::int AS n FROM mandates WHERE owner_did = $1", [org.owner_did]))!.n).toBe(1);
  const stored = await d.db.first<{ body: string }>("SELECT body FROM mandates WHERE owner_did = $1", [org.owner_did]);
  const mandate = JSON.parse(stored!.body);
  expect(mandate.limits).toMatchObject({ per_tx_max: 5000, period_max: 20050 });
  expect(mandate.signature.form).toBe("webauthn");
  const log = (await keyLogState(d, org.owner_did))!;
  expect(verifyMandate(mandate, { keyLog: log, agentDid: agent.did, status: { status: "active" }, origins: d.rp.origins, rpId: d.rp.id })).toMatchObject({ ok: true });

  // A waiting approval of the agent (quorum of one): approved with the passkey.
  const payload = { action: "agent.approval", agent_did: agent.did, title: "Renew the domain", summary: "$12 at registrar.example", risk: "low" };
  await d.db.run("INSERT INTO agent_approvals (id, agent_did, account_id, owner_did, request_id, payload, payload_digest, state, quorum, created_at, expires_at) VALUES ('apr_e2e', $1, $2, $3, 'aar_e2e', $4, $5, 'pending', $6, $7, $8)",
    [agent.did, accountId, org.owner_did, JSON.stringify(payload), payloadDigest(payload), JSON.stringify({ m: 1, of: log.approvers.map((c) => c.kid) }), now(), now() + 300]);
  await page.reload();
  await page.locator("#org-approvals li").first().waitFor();
  expect(await page.locator("#org-approvals li").textContent()).toContain("0 of 1");
  await page.locator("#org-approvals li button", { hasText: "Approve" }).click();
  await expect.poll(async () => (await d.db.first<{ state: string }>("SELECT state FROM agent_approvals WHERE id = 'apr_e2e'"))!.state).toBe("approved");

  // Pause the org: the agent stops, the mandate is revoked, the policy says paused. Resume asks for the passkey.
  await page.click("#org-pause");
  await expect.poll(async () => (await d.db.first<{ state: string }>("SELECT state FROM agents WHERE did = $1", [agent.did]))!.state).toBe("paused");
  expect((await d.db.first<{ revoked_at: number | null }>("SELECT revoked_at FROM mandates WHERE owner_did = $1", [org.owner_did]))!.revoked_at).not.toBeNull();
  await expect.poll(async () => await page.locator("#org-state").textContent()).toContain("Paused");
  await page.click("#org-resume");
  await expect.poll(async () => (await d.db.first<{ state: string }>("SELECT state FROM orgs WHERE id = $1", [org.id]))!.state).toBe("active");
  await expect.poll(async () => (await d.db.first<{ state: string }>("SELECT state FROM agents WHERE did = $1", [agent.did]))!.state).toBe("active");

  expect(errors).toEqual([]);
  await context.close();
});
