import { expect, test } from "vitest";
import { MAX_TRIES, customerIo, newCode, startEmail, verifyEmailCode } from "../src/email.ts";
import { pgliteDb } from "./helpers.ts";

const db = await pgliteDb();
const PEPPER = "test-pepper-not-a-secret";
const T = 1_800_000_000;
const err = async (p: Promise<unknown>) => p.then(() => "ok", (e) => e.code);
const outbox: { email: string; code: string }[] = [];
const send = async (email: string, code: string) => { outbox.push({ email, code }); };
const start = (email: string, installId: string | null = null, t = T) => startEmail(db, { email, installId, pepper: PEPPER, send }, t);
const last = () => outbox[outbox.length - 1].code;

test("codes are exactly 8 digits, leading zeros kept", () => {
  for (let i = 0; i < 2000; i++) expect(newCode()).toMatch(/^\d{8}$/);
});

test("the right code signs in once; the address is normalized; the database holds an HMAC, not the code", async () => {
  const { challengeId, expiresAt } = await start("  Ada@Example.COM ");
  expect(expiresAt).toBe(T + 600);
  expect(outbox.at(-1)!.email).toBe("ada@example.com");
  const row = await db.first("SELECT code_mac FROM email_codes WHERE id = $1", [challengeId]);
  expect(row.code_mac).not.toContain(last());
  expect(await verifyEmailCode(db, { challengeId, code: last(), pepper: PEPPER }, T + 5)).toBe("ada@example.com");
  expect(await err(verifyEmailCode(db, { challengeId, code: last(), pepper: PEPPER }, T + 6))).toBe("code_expired");
});

test("five wrong tries lock the code, even for the right code afterwards", async () => {
  const { challengeId } = await start("lock@example.com");
  const good = last(), bad = good === "00000000" ? "00000001" : "00000000";
  for (let i = 1; i < MAX_TRIES; i++) {
    await expect(verifyEmailCode(db, { challengeId, code: bad, pepper: PEPPER }, T + i)).rejects.toMatchObject({ code: "code_invalid", extra: { tries_left: MAX_TRIES - i } });
  }
  expect(await err(verifyEmailCode(db, { challengeId, code: bad, pepper: PEPPER }, T + 9))).toBe("code_locked");
  expect(await err(verifyEmailCode(db, { challengeId, code: good, pepper: PEPPER }, T + 10))).toBe("code_locked");
});

test("a code expires after 10 minutes; malformed codes are refused without costing a try", async () => {
  const { challengeId } = await start("late@example.com");
  expect(await err(verifyEmailCode(db, { challengeId, code: "1234567", pepper: PEPPER }, T + 1))).toBe("bad_request");
  expect((await db.first("SELECT tries FROM email_codes WHERE id = $1", [challengeId])).tries).toBe(0);
  expect(await err(verifyEmailCode(db, { challengeId, code: last(), pepper: PEPPER }, T + 600))).toBe("code_expired");
});

test("at most 3 codes per address and 10 per install in an hour", async () => {
  for (let i = 0; i < 3; i++) await start("busy@example.com", null, T + i);
  expect(await err(start("busy@example.com", null, T + 10))).toBe("rate_limited");
  expect(await err(start("busy@example.com", null, T + 3601))).toBe("ok");
  for (let i = 0; i < 10; i++) await start(`p${i}@example.com`, "install-1", T + i);
  expect(await err(start("p99@example.com", "install-1", T + 20))).toBe("rate_limited");
});

test("a send failure deletes the code so it does not count against the limits", async () => {
  const failing = async () => { throw Object.assign(new Error("down"), { code: "email_unavailable" }); };
  for (let i = 0; i < 4; i++) expect(await err(startEmail(db, { email: "down@example.com", pepper: PEPPER, send: failing }, T))).toBe("email_unavailable");
  expect(await err(start("down@example.com"))).toBe("ok");
});

test("Customer.io: App API bearer key, the code in the body, no retention, no tracking, the person keyed by an HMAC", async () => {
  let seen: { url: string; init: RequestInit } | undefined;
  const fake = (async (url: string, init: RequestInit) => { seen = { url, init }; return new Response("{}", { status: 200 }); }) as unknown as typeof fetch;
  await customerIo("app-key", PEPPER, fake)("ada@example.com", "01234567");
  expect(seen!.url).toBe("https://api.customer.io/v1/send/email");
  expect((seen!.init.headers as Record<string, string>).authorization).toBe("Bearer app-key");
  const body = JSON.parse(String(seen!.init.body));
  expect(body).toMatchObject({ to: "ada@example.com", from: "Open Entity <updates@openentity.org>", disable_message_retention: true, send_to_unsubscribed: true, tracked: false });
  expect(body.body).toContain("01234567");
  expect(body.plaintext_body).toContain("01234567");
  expect(body.subject).not.toContain("01234567");
  expect(body.identifiers.id).toMatch(/^oe_signin_[0-9a-f]{40}$/);
  expect(JSON.stringify(body.identifiers)).not.toContain("ada@");
  const down = (async () => new Response("no", { status: 500 })) as unknown as typeof fetch;
  expect(await err(customerIo("k", PEPPER, down)("a@b.co", "00000000"))).toBe("email_unavailable");
});
