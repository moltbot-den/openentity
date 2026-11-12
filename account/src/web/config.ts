// Web lane settings: the SSM parameter names its modules read (lambda.ts loads them with the core names) and the
// WebConfig built from them, which reaches every module as Deps.web. A missing value turns its feature off; it never
// falls back to a test value.
import { createPrivateKey, createPublicKey, type KeyObject, type X509Certificate } from "node:crypto";
import type { JWTVerifyGetKey } from "jose";
import { KMSClient } from "@aws-sdk/client-kms";
import type { AppleSiwa, Vault } from "../apple.ts";
import { customerIoMail, type SendMail } from "../email.ts";
import { apnsSender, type Sender } from "../notify.ts";
import type { PlayApi } from "../store.ts";
import { open, seal } from "../seal.ts";
import { APP_ID, BUNDLE_ID } from "../wellknown.ts";

export const WEB_PARAMS = [
  "apns_auth_key", "apns_key_id", "apns_team_id",
  "apple_siwa_key_id", "apple_siwa_private_key",
  "turnstile_site_key", "turnstile_secret",
  "app_review_email", "app_review_code", "app_review_open",
  "test_idp_key", "test_product_seeds",
  "play_push_audience", "play_push_service_account",
];

export interface WebConfig {
  /** APNs through the team's auth key; absent: no iOS pushes (tokens are still stored). */
  apns?: Sender;
  /** The team's Sign in with Apple key: the code exchange at sign-in and token revocation at deletion. */
  apple?: AppleSiwa;
  /** KMS data key sealing (seal.ts), for Apple refresh tokens. */
  vault?: Vault;
  /** The Google web OAuth client id, for Google Identity Services on the web page; absent: no Google button. */
  googleWebClientId?: string;
  /** Turnstile on web sign-up (PLAN 2.3); absent: web sign-up is closed, web sign-in of existing accounts still works. */
  turnstile?: { siteKey: string; secret: string };
  /** Notices to the account email (Customer.io transactional, no retention); absent: notices are push only. */
  sendMail?: SendMail;
  /**
   * App Review access (PLAN 2.3): one allowlisted demo email accepts a fixed code while APP_REVIEW_OPEN is on.
   * `openSince` is the Unix time the release lane turned it on; null means off.
   */
  appReview?: { email: string; code: string; openSince: number | null };
  /** Google Play: the Play Developer API through Workload Identity Federation; absent until the Google project exists. */
  play?: PlayApi;
  /** The Pub/Sub push subscription for Play notifications: its OIDC audience and service account. */
  playPush?: { audience: string; serviceAccount: string; keys?: JWTVerifyGetKey };
  /** Tests only: roots in place of Apple Root CA - G3. */
  appleRoots?: X509Certificate[];
  /** Staging only: Ed25519 keys of the test product identities by name (approve.ts TEST_PRODUCTS). */
  testProducts?: Record<string, KeyObject>;
  /** Staging only: the test identity provider's P-256 key (PLAN 2.3, "No test doors in production"). */
  testIdp?: { privateKey: KeyObject; publicKey: KeyObject };
}

/** Builds the WebConfig from the SSM values by name (the stage-suffixed value already wins). */
export function webConfig(p: Record<string, string | undefined>, env: { DATA_KEY_ID?: string; STAGE?: string } = process.env): WebConfig {
  const since = Number(p.app_review_open), dataKeyId = env.DATA_KEY_ID;
  const kms = dataKeyId ? new KMSClient({}) : undefined;
  // Never in production: the name is read only in staging (and the production role cannot read *_staging values).
  const testKey = env.STAGE === "staging" && p.test_idp_key ? createPrivateKey(p.test_idp_key) : undefined;
  // {"ass": "<base64url 32-byte Ed25519 seed>", ...}: PKCS#8 is the fixed Ed25519 prefix and the seed.
  const seeds: Record<string, string> = env.STAGE === "staging" && p.test_product_seeds ? JSON.parse(p.test_product_seeds) : {};
  const ed25519 = (seed: string) => createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seed, "base64url")]), format: "der", type: "pkcs8" });
  return {
    testProducts: Object.keys(seeds).length ? Object.fromEntries(Object.entries(seeds).map(([n, seed]) => [n, ed25519(seed)])) : undefined,
    testIdp: testKey ? { privateKey: testKey, publicKey: createPublicKey(testKey) } : undefined,
    playPush: p.play_push_audience && p.play_push_service_account ? { audience: p.play_push_audience, serviceAccount: p.play_push_service_account } : undefined,
    apple: p.apple_siwa_key_id && p.apple_siwa_private_key ? { teamId: APP_ID.split(".")[0], keyId: p.apple_siwa_key_id, privateKey: p.apple_siwa_private_key } : undefined,
    vault: kms && dataKeyId ? { seal: (purpose, text) => seal(kms, dataKeyId, purpose, text), open: (purpose, sealed) => open(kms, dataKeyId, purpose, sealed) } : undefined,
    apns: p.apns_auth_key && p.apns_key_id && p.apns_team_id ? apnsSender({ keyPem: p.apns_auth_key, keyId: p.apns_key_id, teamId: p.apns_team_id, topic: BUNDLE_ID }) : undefined,
    googleWebClientId: p.google_oauth_web_client_id?.split(",")[0]?.trim() || undefined,
    turnstile: p.turnstile_site_key && p.turnstile_secret ? { siteKey: p.turnstile_site_key, secret: p.turnstile_secret } : undefined,
    sendMail: p.cio_app_api_key && p.code_pepper ? customerIoMail(p.cio_app_api_key, p.code_pepper) : undefined,
    appReview: p.app_review_email && /^\d{8}$/.test(p.app_review_code ?? "")
      ? { email: p.app_review_email.toLowerCase(), code: p.app_review_code!, openSince: Number.isSafeInteger(since) && since > 0 ? since : null }
      : undefined,
  };
}
