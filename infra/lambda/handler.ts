// The one Lambda: HTTP from CloudFront (site plus /v1 registry) and the per-minute cron from EventBridge Scheduler.
import { GetSecretValueCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { Hono } from "hono";
import { handle } from "hono/aws-lambda";
import { s3Blobs } from "../../registry/src/blob.ts";
import { dataApiDb } from "../../registry/src/db.ts";
import type { Env } from "../../registry/src/env.ts";
import { incorporate, app as registry, scheduled } from "../../registry/src/index.ts";
import { createSite, fsAssets } from "../../site/server/index.ts";

const e = process.env;
type Ready = { env: Env; site: (req: Request) => Promise<Response>; verify: string };
let ready: Promise<Ready> | undefined;

async function init(): Promise<Ready> {
  const res = await new SecretsManagerClient({}).send(new GetSecretValueCommand({ SecretId: e.APP_SECRET_ARN }));
  const s = JSON.parse(res.SecretString!);
  const env: Env = {
    db: dataApiDb({ resourceArn: e.DB_CLUSTER_ARN!, secretArn: e.DB_SECRET_ARN!, database: e.DB_NAME! }),
    log: s3Blobs(e.LOG_BUCKET!),
    snapshots: s3Blobs(e.SNAPSHOT_BUCKET!),
    STAMP_BITS: e.STAMP_BITS!,
    REGISTRY_HOST: e.REGISTRY_HOST!,
    BASE_RPC_URL: e.BASE_RPC_URL!,
    REGISTRY_KEY_JWK: s.REGISTRY_KEY_JWK,
    CUSTODY_KEY: s.CUSTODY_KEY,
    HASH_SALT: s.HASH_SALT,
    TURNSTILE_SECRET: s.TURNSTILE_SECRET,
    CIO_SITE_ID: s.CIO_SITE_ID,
    CIO_API_KEY: s.CIO_API_KEY,
  };
  const site = createSite({
    registry: (req) => Promise.resolve(registry.fetch(req, env)),
    asset: fsAssets(new URL("./dist", import.meta.url).pathname),
    vars: { TURNSTILE_SITE_KEY: e.TURNSTILE_SITE_KEY, CF_ANALYTICS_TOKEN: e.CF_ANALYTICS_TOKEN, SUBSCRIBE_ENABLED: e.SUBSCRIBE_ENABLED },
  });
  return { env, site, verify: s.ORIGIN_VERIFY };
}
const boot = () => (ready ??= init().catch((err) => ((ready = undefined), Promise.reject(err))));

const http = new Hono().all("*", async (c) => {
  const { site, verify } = await boot();
  // Only CloudFront knows this header, so the raw function URL is not a way around the edge.
  if (c.req.header("x-origin-verify") !== verify) return c.text("forbidden", 403);
  const url = new URL(c.req.url);
  url.protocol = "https:";
  url.host = e.REGISTRY_HOST!;
  return site(new Request(url, c.req.raw));
});
const onHttp = handle(http);

export const handler = async (event: any, context: any) => {
  if (event?.source !== "openentity.cron") return onHttp(event, context);
  const { env } = await boot();
  // Same split as before: leaves every minute, stats, snapshot, accreditation and cleanup every tenth minute.
  await (new Date(event.time).getUTCMinutes() % 10 === 0 ? scheduled(env) : incorporate(env));
};
