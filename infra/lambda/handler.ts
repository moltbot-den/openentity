// The one Lambda: HTTP from CloudFront (site plus /v1 registry) and the per-minute cron from EventBridge Scheduler.
import { GetSecretValueCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { Hono } from "hono";
import { handle } from "hono/aws-lambda";
import { s3Blobs } from "../../registry/src/blob.ts";
import { dataApiDb } from "../../registry/src/db.ts";
import type { Env } from "../../registry/src/env.ts";
import { incorporate, app as registry, scheduled } from "../../registry/src/index.ts";
import { createSite, fsAssets } from "../../site/server/index.ts";
import { createMcp } from "../../mcp/src/index.ts";

const e = process.env;
type Ready = { env: Env; site: (req: Request) => Promise<Response>; mcp: (req: Request) => Promise<Response>; verify: string };
let ready: Promise<Ready> | undefined;

async function init(): Promise<Ready> {
  const res = await new SecretsManagerClient({}).send(new GetSecretValueCommand({ SecretId: e.APP_SECRET_ARN }));
  const s = JSON.parse(res.SecretString!);
  const env: Env = {
    db: dataApiDb({ resourceArn: e.DB_CLUSTER_ARN!, secretArn: e.DB_SECRET_ARN!, database: e.DB_NAME! }),
    log: s3Blobs(e.LOG_BUCKET!),
    snapshots: e.SNAPSHOT_BUCKET ? s3Blobs(e.SNAPSHOT_BUCKET) : undefined,
    IP_DAILY_LIMIT: e.IP_DAILY_LIMIT,
    WRITE_PER_MINUTE: e.WRITE_PER_MINUTE,
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
  const reg = (req: Request) => Promise.resolve(registry.fetch(req, env));
  // The MCP door runs in-process and mints stamps on the caller's behalf, so a stamp would only cost this Lambda
  // (about 15 s at 20 bits). It runs at 0 bits; per-IP limits still apply (spec 10.4, PRD 7.6).
  const mcpReg = (req: Request) => Promise.resolve(registry.fetch(req, { ...env, STAMP_BITS: "0" }));
  const site = createSite({
    registry: reg,
    asset: fsAssets(new URL("./dist", import.meta.url).pathname),
    vars: { TURNSTILE_SITE_KEY: e.TURNSTILE_SITE_KEY, CF_ANALYTICS_TOKEN: e.CF_ANALYTICS_TOKEN, SUBSCRIBE_ENABLED: e.SUBSCRIBE_ENABLED },
  });
  return { env, site, mcp: createMcp({ registry: mcpReg, site }), verify: s.ORIGIN_VERIFY };
}
const boot = () => (ready ??= init().catch((err) => ((ready = undefined), Promise.reject(err))));

// A Lambda timeout reaches the caller as CloudFront's HTML 504, which breaks agent loops that parse JSON.
// Answer first, as JSON, a few seconds before the 30 s limit. A retried write that already landed gets the registry's 409.
export function withDeadline(work: Promise<Response>, ms = 26_000): Promise<Response> {
  let timer: NodeJS.Timeout;
  const late = new Promise<Response>((r) => {
    timer = setTimeout(() => r(Response.json({ error: "timeout", message: "no answer in time; retry with a new stamp" }, { status: 503, headers: { "retry-after": "2" } })), ms);
  });
  return Promise.race([work, late]).finally(() => clearTimeout(timer));
}

const http = new Hono().all("*", (c) => withDeadline(route(c.req.raw, c.req.header.bind(c.req))));
async function route(raw: Request, header: (k: string) => string | undefined): Promise<Response> {
  const { site, mcp, verify } = await boot();
  // Only CloudFront knows this header, so the raw function URL is not a way around the edge.
  if (header("x-origin-verify") !== verify) return new Response("forbidden", { status: 403 });
  // The mcp.openentity.org distribution adds this header at the origin; CloudFront does not forward the viewer Host.
  if (header("x-oe-site") === "mcp") return mcp(raw);
  const url = new URL(raw.url);
  url.protocol = "https:";
  url.host = e.REGISTRY_HOST!;
  return site(new Request(url, raw));
}
const onHttp = handle(http);

export const handler = async (event: any, context: any) => {
  if (event?.source !== "openentity.cron") return onHttp(event, context);
  const { env } = await boot();
  // Same split as before: leaves every minute, stats, snapshot, accreditation and cleanup every tenth minute.
  await (new Date(event.time).getUTCMinutes() % 10 === 0 ? scheduled(env) : incorporate(env));
};
