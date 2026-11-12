// The account service's one function: HTTP from CloudFront (function URL) and the agent WebSocket routes.
import { createHash, timingSafeEqual } from "node:crypto";
import { KMSClient } from "@aws-sdk/client-kms";
import { GetParametersCommand, SSMClient } from "@aws-sdk/client-ssm";
import { Hono } from "hono";
import { handle } from "hono/aws-lambda";
import { createApp } from "./app.ts";
import { awake, dataApiDb } from "./db.ts";
import { customerIo } from "./email.ts";
import { fail } from "./http.ts";
import { kmsEd25519, kmsEs256, kmsKey } from "./keys.ts";
import { rpFor } from "./passkey.ts";
import { dataKey } from "./seal.ts";
import { BUNDLE_ID } from "./wellknown.ts";

const e = process.env;
// Logical names read from SSM: <name> (both stages) and <name>_<prod|staging> (this stage wins). The role cannot read the other stage's values.
const NAMES = ["code_pepper", "data_key", "cio_app_api_key", "apple_siwa_services_id", "google_oauth_ios_client_id", "google_oauth_web_client_id", "android_cert_sha256"];

async function params(): Promise<Record<string, string | undefined>> {
  const ssm = new SSMClient({});
  const want = NAMES.flatMap((n) => [`${e.PARAM_PATH}${n}`, `${e.PARAM_PATH}${n}_${e.PARAM_SUFFIX}`]);
  const got: Record<string, string> = {};
  for (let i = 0; i < want.length; i += 10) {
    const r = await ssm.send(new GetParametersCommand({ Names: want.slice(i, i + 10), WithDecryption: true }));
    for (const p of r.Parameters ?? []) got[p.Name!] = p.Value!;
  }
  return Object.fromEntries(NAMES.map((n) => [n, got[`${e.PARAM_PATH}${n}_${e.PARAM_SUFFIX}`] ?? got[`${e.PARAM_PATH}${n}`]]));
}

const list = (v?: string) => (v ?? "").split(",").map((s) => s.trim()).filter(Boolean);

async function init() {
  const s = await params();
  if (!s.code_pepper) throw new Error("code_pepper is not set in SSM");
  dataKey(s.data_key); // fail at boot, not at the first Apple sign-in, if the data key is missing
  const kms = new KMSClient({});
  // ponytail: the close key signs nothing until account deletion lands; its signer must then normalize s to low-S (keylog-1).
  const [token, did, close] = await Promise.all([kmsKey(kms, e.TOKEN_KEY_ID!, kmsEs256), kmsKey(kms, e.DID_KEY_ID!, kmsEd25519), kmsKey(kms, e.CLOSE_KEY_ID!, kmsEs256)]);
  const fingerprints = list(s.android_cert_sha256);
  const app = createApp({
    stage: e.STAGE === "production" ? "production" : "staging",
    host: e.HOST!,
    db: awake(dataApiDb({ resourceArn: e.DB_CLUSTER_ARN!, secretArn: e.DB_SECRET_ARN!, database: e.DB_NAME! })),
    keys: { token, did, close },
    pepper: s.code_pepper,
    sendCode: s.cio_app_api_key ? customerIo(s.cio_app_api_key, s.code_pepper) : async () => fail(503, "email_unavailable", "email sign-in is not configured in this environment"),
    // android:apk-key-hash:<base64url SHA-256 of the signing certificate>, from the hex fingerprints assetlinks.json publishes.
    rp: rpFor(e.HOST!, fingerprints.map((f) => `android:apk-key-hash:${Buffer.from(f.replace(/:/g, ""), "hex").toString("base64url")}`)),
    apple: { native: [BUNDLE_ID], web: list(s.apple_siwa_services_id) },
    google: [...list(s.google_oauth_ios_client_id), ...list(s.google_oauth_web_client_id)],
    androidFingerprints: fingerprints,
    signinOpen: e.SIGNIN_OPEN === "1",
    version: e.AWS_LAMBDA_FUNCTION_VERSION,
  });
  return { app, verify: e.ORIGIN_VERIFY! };
}
let ready: ReturnType<typeof init> | undefined;
const boot = () => (ready ??= init().catch((err) => ((ready = undefined), Promise.reject(err))));

/** Constant-time comparison of the origin header with the secret (hashing first equalizes the lengths). */
export function sameSecret(given: string, secret: string): boolean {
  const h = (v: string) => createHash("sha256").update(v).digest();
  return timingSafeEqual(h(given), h(secret));
}

const http = new Hono().all("*", async (c) => {
  const { app, verify } = await boot();
  // Only CloudFront knows this header, so the raw function URL is not a way around the edge.
  if (!verify || !sameSecret(c.req.header("x-origin-verify") ?? "", verify)) return c.text("forbidden", 403);
  const url = new URL(c.req.url);
  url.protocol = "https:";
  url.host = e.HOST!;
  return app.fetch(new Request(url, c.req.raw));
});
const onHttp = handle(http);

export const handler = async (event: any, context: any) => {
  const route = event?.requestContext?.routeKey;
  if (event?.requestContext?.connectionId && route) {
    // WebSocket (PLAN 8.2). Pairing lands on Day 3; until then no agent is paired, so every connection is refused.
    if (route === "$connect") return { statusCode: 403, body: "not paired" };
    return { statusCode: 200 };
  }
  return onHttp(event, context);
};
