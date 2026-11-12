// The account service's one function: HTTP from CloudFront (function URL), the agent WebSocket routes and the
// scheduled jobs tick (EventBridge).
import { createHash, timingSafeEqual } from "node:crypto";
import { KMSClient } from "@aws-sdk/client-kms";
import { SendMessageBatchCommand, SQSClient } from "@aws-sdk/client-sqs";
import { GetParametersCommand, SSMClient } from "@aws-sdk/client-ssm";
import { Hono } from "hono";
import { handle } from "hono/aws-lambda";
import { type Deps, createApp } from "./app.ts";
import { s3Blobs } from "./blobs.ts";
import { awake, dataApiDb } from "./db.ts";
import type { QueuedEvent } from "./events.ts";
import { customerIo } from "./email.ts";
import { fail } from "./http.ts";
import { PRODUCT_APIS } from "./outbound.ts";
import { runJobs } from "./jobs.ts";
import { kmsEd25519, kmsEs256, kmsKey } from "./keys.ts";
import { rpFor } from "./passkey.ts";
import { PARAM_NAMES, STAGE_SUFFIX, type Stage, paramNames, stageOf } from "./params.ts";
import { webConfig } from "./web/config.ts";
import { apiGatewayWs, wsEvent } from "./ws.ts";
import { BUNDLE_ID } from "./wellknown.ts";

const e = process.env;
/** The SSM values (params.ts names): this stage's suffixed value wins over the shared one. */
async function params(stage: Stage): Promise<Record<string, string | undefined>> {
  const ssm = new SSMClient({});
  const want = paramNames(stage).map((n) => `${e.PARAM_PATH}${n}`);
  const got: Record<string, string> = {};
  for (let i = 0; i < want.length; i += 10) {
    const r = await ssm.send(new GetParametersCommand({ Names: want.slice(i, i + 10), WithDecryption: true }));
    for (const p of r.Parameters ?? []) got[p.Name!] = p.Value!;
  }
  return Object.fromEntries(PARAM_NAMES.map((n) => [n, got[`${e.PARAM_PATH}${n}_${STAGE_SUFFIX[stage]}`] ?? got[`${e.PARAM_PATH}${n}`]]));
}

const list = (v?: string) => (v ?? "").split(",").map((s) => s.trim()).filter(Boolean);

async function init() {
  const stage = stageOf(e.STAGE); // first: an unknown STAGE starts nothing (gate hardening)
  const s = await params(stage);
  if (!s.code_pepper) throw new Error("code_pepper is not set in SSM");
  const kms = new KMSClient({});
  // The close key signs key log close entries only; keylog.ts closeKeyLog normalizes its s to low-S (keylog-1).
  const [token, did, close] = await Promise.all([kmsKey(kms, e.TOKEN_KEY_ID!, kmsEs256), kmsKey(kms, e.DID_KEY_ID!, kmsEd25519), kmsKey(kms, e.CLOSE_KEY_ID!, kmsEs256)]);
  const fingerprints = list(s.android_cert_sha256);
  const deps: Deps = {
    stage,
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
    web: webConfig(s),
    ws: apiGatewayWs(e.WS_CALLBACK_URL!),
    queue: sqsQueue(e.EVENTS_QUEUE_URL!),
    blobs: e.ATTACHMENTS_BUCKET ? s3Blobs(e.ATTACHMENTS_BUCKET) : undefined,
    // Product API hosts by DID. Production calls the products; staging calls none unless product_apis names stubs.
    products: s.product_apis ? JSON.parse(s.product_apis) : stage === "production" ? PRODUCT_APIS : {},
  };
  return { deps, app: createApp(deps), verify: e.ORIGIN_VERIFY! };
}
/** One SQS message per event (the forwarder validates and sends each), ten to a batch. */
function sqsQueue(url: string) {
  const sqs = new SQSClient({});
  return async (events: QueuedEvent[]) => {
    for (let i = 0; i < events.length; i += 10) {
      const batch = events.slice(i, i + 10);
      const r = await sqs.send(new SendMessageBatchCommand({ QueueUrl: url, Entries: batch.map((ev, n) => ({ Id: String(n), MessageBody: JSON.stringify(ev) })) }));
      if (r.Failed?.length) throw new Error(`${r.Failed.length} events were not queued: ${r.Failed[0].Message}`);
    }
  };
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
  // EventBridge schedule (account-stack.ts): run the jobs. Only EventBridge can send this shape; HTTP events never carry it.
  if (event?.source === "aws.events") return runJobs((await boot()).deps);
  // The agent WebSocket (PLAN 8.2): $connect, $disconnect, sync, ack and $default. Heartbeats never reach the function.
  if (event?.requestContext?.connectionId && event.requestContext.routeKey) return wsEvent((await boot()).deps, event);
  return onHttp(event, context);
};
