// Apple and Google identity tokens (PLAN 2.3). Signatures, issuer, audience and expiry through jose; the nonce here.
// Every provider gets lowercase hex SHA-256 of the raw nonce the account service issued (POST /v1/auth/nonce), so an
// identity token alone, without the raw nonce only the client holds, cannot be replayed.
import { createHash } from "node:crypto";
import { createRemoteJWKSet, errors, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from "jose";
import { HttpError } from "./http.ts";

const APPLE_ISSUER = "https://appleid.apple.com";
const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"];
export const appleKeys = createRemoteJWKSet(new URL("https://appleid.apple.com/auth/keys"));
export const googleKeys = createRemoteJWKSet(new URL("https://www.googleapis.com/oauth2/v3/certs"));

export const nonceHash = (raw: string) => createHash("sha256").update(raw, "utf8").digest("hex");

export interface Identity {
  provider: "apple" | "google";
  sub: string;
  /** Set only when the provider vouches for it (email_verified). */
  email: string | null;
  emailPrivate: boolean;
  aud: string;
}

const truthy = (v: unknown) => v === true || v === "true";

/** The nonce a token must carry: the raw nonce this client was issued, or (Apple's form_post return) its stored hash. */
export type NonceCheck = { nonce: string } | { nonceHash: string };
const expected = (n: NonceCheck) => ("nonce" in n ? nonceHash(n.nonce) : n.nonceHash);

async function verify(token: string, keys: JWTVerifyGetKey, issuer: string | string[], audience: string[], hash: string): Promise<JWTPayload> {
  if (!audience.length) throw new HttpError(503, "unavailable", "this sign-in method is not configured");
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, keys, { issuer, audience, algorithms: ["RS256", "ES256"], clockTolerance: 30 }));
  } catch (e) {
    if (e instanceof errors.JOSEError) throw new HttpError(401, "id_token_invalid", `identity token rejected: ${e.code}`);
    throw e;
  }
  // Exactly one audience: a token minted for several clients is not one of ours.
  if (Array.isArray(payload.aud) && payload.aud.length !== 1) throw new HttpError(401, "id_token_invalid", "identity token names several audiences");
  if (typeof payload.sub !== "string" || !payload.sub) throw new HttpError(401, "id_token_invalid", "identity token has no subject");
  if (typeof payload.nonce !== "string" || payload.nonce !== hash) throw new HttpError(401, "nonce_invalid", "the token's nonce is not the SHA-256 of the nonce this client was issued");
  return payload;
}

/** `audience`: the bundle ID for the native sheet, the Services ID for the web and Android redirect. */
export async function verifyApple(token: string, o: { audience: string[]; keys?: JWTVerifyGetKey } & NonceCheck): Promise<Identity> {
  const p = await verify(token, o.keys ?? appleKeys, APPLE_ISSUER, o.audience, expected(o));
  const email = typeof p.email === "string" && truthy(p.email_verified) ? p.email.toLowerCase() : null;
  return { provider: "apple", sub: p.sub!, email, emailPrivate: truthy(p.is_private_email), aud: String(p.aud) };
}

/** `audience`: the iOS client ID and the web client ID (Android Credential Manager tokens carry the web client ID). */
export async function verifyGoogle(token: string, o: { audience: string[]; keys?: JWTVerifyGetKey } & NonceCheck): Promise<Identity> {
  const p = await verify(token, o.keys ?? googleKeys, GOOGLE_ISSUERS, o.audience, expected(o));
  const email = typeof p.email === "string" && p.email_verified === true ? p.email.toLowerCase() : null;
  return { provider: "google", sub: p.sub!, email, emailPrivate: false, aud: String(p.aud) };
}
