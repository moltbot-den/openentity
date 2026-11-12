// 8-digit email codes (PLAN 2.3): valid 10 minutes, 5 tries, at most 3 codes per address and 10 per install an hour.
// With 8 digits a sustained attacker has about a 0.01% chance a month per address. Only an HMAC of the code is stored.
import { createHmac, randomInt, timingSafeEqual } from "node:crypto";
import { type Db, newId, now } from "./db.ts";
import { HttpError, fail } from "./http.ts";

export const CODE_TTL = 600, MAX_TRIES = 5, PER_ADDRESS_PER_HOUR = 3, PER_INSTALL_PER_HOUR = 10;
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,253}\.[^\s@]{2,}$/;

export const newCode = () => String(randomInt(0, 100_000_000)).padStart(8, "0");
const mac = (pepper: string, id: string, code: string) => createHmac("sha256", pepper).update(`${id}:${code}`).digest("hex");

export function normalizeEmail(raw: unknown): string {
  const email = String(raw ?? "").trim().toLowerCase();
  if (email.length > 254 || !EMAIL.test(email)) fail(400, "email_invalid", "a valid email address is required");
  return email;
}

export type SendCode = (email: string, code: string) => Promise<void>;

/** `human` false: a web start without Turnstile; the verify call must then prove Turnstile itself. */
export async function startEmail(db: Db, o: { email: string; installId?: string | null; pepper: string; send: SendCode; human?: boolean }, t = now()) {
  const email = normalizeEmail(o.email);
  const count = async (col: string, v: string) =>
    Number((await db.first<{ n: number }>(`SELECT count(*) AS n FROM email_codes WHERE ${col} = $1 AND created_at > $2`, [v, t - 3600]))!.n);
  if ((await count("email", email)) >= PER_ADDRESS_PER_HOUR) fail(429, "rate_limited", "too many codes for this address; try again within the hour", { retry_after: 3600 });
  if (o.installId && (await count("install_id", o.installId)) >= PER_INSTALL_PER_HOUR) fail(429, "rate_limited", "too many codes from this install; try again within the hour", { retry_after: 3600 });
  const id = newId("eml"), code = newCode();
  await db.run("INSERT INTO email_codes (id, email, code_mac, install_id, human, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    [id, email, mac(o.pepper, id, code), o.installId ?? null, o.human ?? true, t, t + CODE_TTL]);
  try {
    await o.send(email, code);
  } catch (e) {
    await db.run("DELETE FROM email_codes WHERE id = $1", [id]); // an unsent code does not count against the limits
    throw e;
  }
  return { challengeId: id, expiresAt: t + CODE_TTL };
}

type Outcome = { email: string } | { error: HttpError };

/**
 * Returns the verified address. A wrong code costs a try; the fifth wrong try locks the code. `fixed` is the App Review
 * demo address and its fixed code (PLAN 2.3), passed only while APP_REVIEW_OPEN is on; it opens that address's codes only.
 */
export async function verifyEmailCode(db: Db, o: { challengeId: string; code: string; pepper: string; fixed?: { email: string; code: string } }, t = now()): Promise<string> {
  if (!/^\d{8}$/.test(o.code ?? "")) fail(400, "bad_request", "the code is 8 digits");
  // A wrong try must commit before the error goes out, so the transaction returns the outcome.
  const out = await db.tx<Outcome>(async (tx) => {
    const row = await tx.first<{ email: string; code_mac: string; tries: number; expires_at: number; used_at: number | null }>(
      "SELECT email, code_mac, tries, expires_at, used_at FROM email_codes WHERE id = $1 FOR UPDATE", [o.challengeId]);
    if (!row || row.used_at !== null || Number(row.expires_at) <= t) return { error: new HttpError(410, "code_expired", "this code has expired or was used; request a new one") };
    if (row.tries >= MAX_TRIES) return { error: new HttpError(410, "code_locked", "too many wrong tries; request a new code") };
    const review = !!o.fixed && row.email === o.fixed.email && timingSafeEqual(Buffer.from(o.code), Buffer.from(o.fixed.code));
    const ok = review || timingSafeEqual(Buffer.from(row.code_mac, "hex"), Buffer.from(mac(o.pepper, o.challengeId, o.code), "hex"));
    if (!ok) {
      const tries = row.tries + 1;
      await tx.run("UPDATE email_codes SET tries = $2 WHERE id = $1", [o.challengeId, tries]);
      return { error: tries >= MAX_TRIES
        ? new HttpError(410, "code_locked", "too many wrong tries; request a new code")
        : new HttpError(401, "code_invalid", "wrong code", { tries_left: MAX_TRIES - tries }) };
    }
    await tx.run("UPDATE email_codes SET used_at = $2 WHERE id = $1", [o.challengeId, t]);
    return { email: row.email };
  });
  if ("error" in out) throw out.error;
  return out.email;
}

export type SendMail = (email: string, subject: string, text: string, html?: string) => Promise<void>;

/**
 * Customer.io transactional email without a template (the App API's "uncategorized" message). The body is not retained
 * by Customer.io, so a code never sits in its delivery log. The person is identified by an HMAC of the address, not
 * the address, so sign-in recipients never join the newsletter audience.
 */
export function customerIoMail(apiKey: string, pepper: string, fetchImpl: typeof fetch = fetch): SendMail {
  return async (email, subject, text, html) => {
    const res = await fetchImpl("https://api.customer.io/v1/send/email", {
      method: "POST",
      headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
      body: JSON.stringify({
        to: email,
        from: "Open Entity <updates@openentity.org>",
        subject,
        body: html ?? `<p>${text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/\n\n/g, "</p><p>").replace(/\n/g, "<br>")}</p>`,
        plaintext_body: text,
        identifiers: { id: `oe_signin_${createHmac("sha256", pepper).update(`cio:${email}`).digest("hex").slice(0, 40)}` },
        disable_message_retention: true,
        send_to_unsubscribed: true,
        tracked: false,
      }),
      signal: AbortSignal.timeout(5000),
    }).catch(() => fail(502, "email_unavailable", "the email provider could not be reached"));
    if (!res.ok) fail(502, "email_unavailable", `the email provider answered ${res.status}`);
  };
}

/** The 8-digit sign-in code email. */
export function customerIo(apiKey: string, pepper: string, fetchImpl: typeof fetch = fetch): SendCode {
  const send = customerIoMail(apiKey, pepper, fetchImpl);
  return (email, code) => send(email, "Your Open Entity sign-in code",
    `Your Open Entity sign-in code is ${code}.\n\nIt expires in 10 minutes. If you did not ask for it, you can ignore this email.`,
    `<p>Your Open Entity sign-in code is</p><p style="font-size:28px;font-weight:600;letter-spacing:4px;font-family:monospace">${code}</p><p>It expires in 10 minutes. If you did not ask for it, you can ignore this email.</p>`);
}
