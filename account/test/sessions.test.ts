import { expect, test } from "vitest";
import { APP_TTL, RETRY_GRACE, WEB_TTL, openSession, revoke, rotate, tokenHash } from "../src/sessions.ts";
import { account, pgliteDb } from "./helpers.ts";

const db = await pgliteDb();
const T = 1_800_000_000;
const err = async (p: Promise<unknown>) => p.then(() => "ok", (e) => e.code);
const app = async () => openSession(db, { accountId: await account(db), platform: "ios", amr: "apple", installId: "i-1" }, T);

test("only the SHA-256 of a refresh token is stored, and the token is 256 random bits", async () => {
  const s = await app();
  expect(s.refreshToken).toMatch(/^oert_[A-Za-z0-9_-]{43}$/);
  expect(await db.first("SELECT 1 FROM refresh_tokens WHERE hash = $1", [s.refreshToken])).toBeNull();
  expect(await db.first("SELECT 1 FROM refresh_tokens WHERE hash = $1", [tokenHash(s.refreshToken)])).not.toBeNull();
});

test("every use rotates the token; the app session slides to 90 days from the last use", async () => {
  const s = await app();
  const r1 = await rotate(db, s.refreshToken, T + 100);
  expect(r1.refreshToken).not.toBe(s.refreshToken);
  expect(r1.expiresAt).toBe(T + 100 + APP_TTL);
  const r2 = await rotate(db, r1.refreshToken, T + 200);
  expect(r2.session.id).toBe(r1.session.id);
});

test("reuse of a rotated token revokes the whole family, including the newest token", async () => {
  const s = await app();
  const r1 = await rotate(db, s.refreshToken, T + 10);
  const r2 = await rotate(db, r1.refreshToken, T + 20); // the successor was used, so no retry grace applies
  expect(await err(rotate(db, s.refreshToken, T + 25))).toBe("token_reused");
  expect(await err(rotate(db, r2.refreshToken, T + 30))).toBe("invalid_grant");
  expect((await db.first("SELECT revoke_reason FROM sessions WHERE id = $1", [s.sessionId])).revoke_reason).toBe("token_reused");
});

test("a retry within 30 s whose successor was never used gets a fresh successor and kills the unused one", async () => {
  const s = await app();
  const lost = await rotate(db, s.refreshToken, T + 10); // response lost on the network
  const retry = await rotate(db, s.refreshToken, T + 10 + RETRY_GRACE);
  expect(retry.session.id).toBe(lost.session.id);
  expect(await err(rotate(db, lost.refreshToken, T + 50))).toBe("invalid_grant");
  expect(await err(rotate(db, retry.refreshToken, T + 60))).toBe("ok");
});

test("the same retry after 30 s is reuse", async () => {
  const s = await app();
  await rotate(db, s.refreshToken, T + 10);
  expect(await err(rotate(db, s.refreshToken, T + 11 + RETRY_GRACE))).toBe("token_reused");
});

test("the retry window runs from the first use, so repeated retries cannot stretch it", async () => {
  const s = await app();
  await rotate(db, s.refreshToken, T + 10);
  await rotate(db, s.refreshToken, T + 30);
  expect(await err(rotate(db, s.refreshToken, T + 45))).toBe("token_reused");
});

test("unknown, expired and revoked tokens are invalid_grant", async () => {
  expect(await err(rotate(db, "oert_unknown", T))).toBe("invalid_grant");
  const s = await app();
  expect(await err(rotate(db, s.refreshToken, T + APP_TTL + 1))).toBe("invalid_grant");
  const v = await app();
  await revoke(db, v.refreshToken, "signed_out", T + 5);
  expect(await err(rotate(db, v.refreshToken, T + 6))).toBe("invalid_grant");
  await revoke(db, "oert_unknown"); // RFC 7009: unknown tokens are not an error
});

test("a web session ends 12 hours after sign-in however often it refreshes", async () => {
  const w = await openSession(db, { accountId: await account(db), platform: "web", amr: "passkey" }, T);
  const r = await rotate(db, w.refreshToken, T + WEB_TTL - 60);
  expect(r.expiresAt).toBe(T + WEB_TTL);
  expect(await err(rotate(db, r.refreshToken, T + WEB_TTL))).toBe("invalid_grant");
});

test("a paused staging cluster is waited for, other errors are not", async () => {
  const { awake } = await import("../src/db.ts");
  let calls = 0;
  const resuming = Object.assign(new Error("resuming"), { name: "DatabaseResumingException" });
  const flaky = { ...db, first: (async () => { if (++calls < 3) throw resuming; return { ok: 1 }; }) as typeof db.first };
  expect(await awake(flaky, async () => {}).first("SELECT 1")).toEqual({ ok: 1 });
  expect(calls).toBe(3);
  const broken = { ...db, first: (async () => { throw new Error("syntax error"); }) as typeof db.first };
  await expect(awake(broken, async () => {}).first("SELECT 1")).rejects.toThrow("syntax error");
  const never = { ...db, first: (async () => { throw resuming; }) as typeof db.first };
  await expect(awake(never, async () => {}, 4000).first("SELECT 1")).rejects.toThrow("resuming");
});
