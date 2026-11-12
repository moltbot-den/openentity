// Analytics events (core lane, PLAN 13.1): the app's own events (POST /v1/events; before sign-up with an install token
// from POST /v1/installs) and the products' (POST /v1/events/ingest, product-signed). Each is checked against
// account/analytics/events.yaml by the Monitoring lane's validator and queued for its forwarder (SQS). The only person
// identifier is user_id, an HMAC of the owner DID; the catalog forbids message text, secret paths, photos and emails.
import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import type { Context, Hono } from "hono";
import { type QueuedEvent, validateEvent } from "../analytics/src/validate.ts";
import type { Deps } from "./app.ts";
import { bump, now } from "./db.ts";
import { bearer, fail, ipOf, json } from "./http.ts";
import { productSigned } from "./rfc9421.ts";

export type { QueuedEvent };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const APP_MAX = 50, APP_BYTES = 32_768, INGEST_MAX = 100, APP_PER_MINUTE = 120;

/** user_id: an HMAC of the owner DID (or the account id before a key log), so tools never see the DID. */
export const userId = (d: Deps, owner: string) => createHmac("sha256", d.pepper).update(`analytics|${owner}`).digest("hex");
const installMac = (d: Deps, install: string, platform: string) => createHmac("sha256", d.pepper).update(`install|${install}|${platform}`).digest("base64url");

/** The install token's platform when `token` was issued for `install`, else null. */
function installPlatform(d: Deps, token: string | undefined, install: string): string | null {
  const m = /^oeit_(ios|android|web)\.([A-Za-z0-9_-]{43})$/.exec(token ?? "");
  if (!m) return null;
  const want = Buffer.from(installMac(d, install, m[1])), got = Buffer.from(m[2]);
  return want.length === got.length && timingSafeEqual(want, got) ? m[1] : null;
}

/**
 * The service's own server events (catalog source `server`): pairing, pause, messages, key log changes. Checked like
 * any other event; one that fails the catalog is logged and dropped. Never throws: analytics never fails a request.
 */
export async function track(d: Deps, event: string, props: Record<string, string | number | boolean>, o: { owner?: string | null; agent?: string } = {}) {
  const v = validateEvent({
    event, props: { ...props, ...(o.agent ? { agent_did: o.agent } : {}) }, event_id: randomUUID(), ts_ms: Date.now(), platform: "server",
    ...(o.owner ? { user_id: userId(d, o.owner) } : {}),
  }, { allow: ["server"] });
  if (!v.ok) return void console.warn(`analytics: ${v.error}`);
  await enqueue(d, [v.event]).catch((e) => console.warn(`analytics: ${(e as Error).message}`));
}

async function enqueue(d: Deps, events: QueuedEvent[]) {
  if (!events.length) return;
  if (!d.queue) return; // tests and local runs without the forwarder
  await d.queue(events);
}

/** Validates each event; answers EventsAccepted with the rejects by index. */
async function accept(d: Deps, list: QueuedEvent[], allow: ("client" | "web" | "server")[]) {
  const ok: QueuedEvent[] = [], rejected: { index: number; error: string }[] = [];
  list.forEach((e, index) => {
    const v = validateEvent(e, { allow });
    if (v.ok) ok.push(v.event);
    else rejected.push({ index, error: v.error });
  });
  await enqueue(d, ok);
  return { accepted: ok.length, rejected };
}

export function routes(app: Hono, d: Deps) {
  app.post("/v1/installs", async (c) => {
    const b = await json(c);
    if (typeof b.install_id !== "string" || !UUID.test(b.install_id) || !["ios", "android", "web"].includes(b.platform)) fail(400, "bad_request", "install_id (a UUID) and platform are required");
    if ((await bump(d.db, `installs:${createHash("sha256").update(ipOf(c)).digest("hex").slice(0, 32)}`, String(Math.floor(now() / 60)))) > 30) fail(429, "rate_limited", "too many installs from this address", { retry_after: 60 });
    return c.json({ install_token: `oeit_${b.platform}.${installMac(d, b.install_id.toLowerCase(), b.platform)}` }, 201);
  });

  app.post("/v1/events", async (c) => {
    if ((await c.req.text()).length > APP_BYTES) fail(413, "too_large", "at most 32 KB of events a call");
    const b = await json(c);
    const install = typeof b.install_id === "string" && UUID.test(b.install_id) ? b.install_id.toLowerCase() : fail(400, "bad_request", "install_id (a UUID) is required");
    let who: Pick<QueuedEvent, "user_id" | "platform" | "app_version">;
    if (c.req.header("authorization")) {
      const o = await bearer(c, d);
      const s = await d.db.first<{ platform: string; app_version: string | null }>("SELECT platform, app_version FROM sessions WHERE id = $1", [o.sid]);
      who = { user_id: userId(d, o.ownerDid ?? o.accountId), platform: s!.platform as QueuedEvent["platform"], ...(s!.app_version ? { app_version: s!.app_version.replace(/[^A-Za-z0-9_.:-]/g, "_").slice(0, 64) } : {}) };
    } else {
      const platform = installPlatform(d, c.req.header("x-oe-install-token"), install) ?? fail(401, "unauthorized", "send a bearer token, or X-OE-Install-Token from POST /v1/installs");
      who = { platform: platform as QueuedEvent["platform"] };
    }
    if (!Array.isArray(b.events) || !b.events.length || b.events.length > APP_MAX) fail(400, "bad_request", `events is 1 to ${APP_MAX} events`);
    if ((await bump(d.db, `events:${install}`, String(Math.floor(now() / 60)))) > APP_PER_MINUTE) fail(429, "rate_limited", "too many event calls from this install", { retry_after: 60 });
    const list = (b.events as any[]).map((e) => ({ event: e?.name, props: e?.properties ?? {}, event_id: e?.insert_id, ts_ms: e?.time, install_id: install, ...who }) as QueuedEvent);
    return c.json(await accept(d, list, ["client", "web"]), 202);
  });

  app.post("/v1/events/ingest", async (c: Context) => {
    await productSigned(c, d);
    const b = await json(c);
    if (!Array.isArray(b.events) || !b.events.length || b.events.length > INGEST_MAX) fail(400, "bad_request", `events is 1 to ${INGEST_MAX} events`);
    const list = (b.events as any[]).map((e) => ({
      event: e?.name, props: { ...(e?.properties ?? {}), ...(typeof e?.agent_did === "string" ? { agent_did: e.agent_did } : {}) },
      event_id: e?.insert_id, ts_ms: e?.time, platform: "server", ...(typeof e?.owner_did === "string" ? { user_id: userId(d, e.owner_did) } : {}),
    }) as QueuedEvent);
    return c.json(await accept(d, list, ["server"]), 202);
  });
}
