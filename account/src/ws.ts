// Agent channel (PLAN 8.2, openapi.yaml x-websocket): API Gateway WebSocket at wss://agents.<host>/. $connect checks an
// RFC 9421 signature by a paired agent's did:key; items wait in `inbox` until acknowledged and go out through
// @connections as they arrive. Heartbeats are a MOCK route in the stack and never reach the function.
import { ApiGatewayManagementApiClient, DeleteConnectionCommand, GoneException, PostToConnectionCommand } from "@aws-sdk/client-apigatewaymanagementapi";
import type { Deps } from "./app.ts";
import { newId, now } from "./db.ts";
import { HttpError } from "./http.ts";
import { verifySigned } from "./rfc9421.ts";

/** Sends frames to open sockets. post answers false when the socket is gone. */
export interface WsClient { post(connectionId: string, frame: unknown): Promise<boolean>; close(connectionId: string): Promise<void> }

export function apiGatewayWs(callbackUrl: string): WsClient {
  const api = new ApiGatewayManagementApiClient({ endpoint: callbackUrl });
  return {
    async post(id, frame) {
      try {
        await api.send(new PostToConnectionCommand({ ConnectionId: id, Data: new TextEncoder().encode(JSON.stringify(frame)) }));
        return true;
      } catch (e) {
        if (e instanceof GoneException) return false;
        throw e;
      }
    },
    async close(id) {
      await api.send(new DeleteConnectionCommand({ ConnectionId: id })).catch((e) => { if (!(e instanceof GoneException)) throw e; });
    },
  };
}

type Frame = { type: string; [k: string]: unknown };

/** Pushes a frame to the agent's socket if one is open; a gone socket is forgotten. */
async function push(d: Deps, agentDid: string, connectionId: string | null, frame: unknown) {
  if (!connectionId || !d.ws) return;
  if (!(await d.ws.post(connectionId, frame).catch((e) => (console.warn(`post to ${agentDid} failed`, e), true)))) {
    await d.db.run("UPDATE agents SET connection_id = NULL WHERE did = $1 AND connection_id = $2", [agentDid, connectionId]);
  }
}

/** Queues a frame for the agent (kept until acknowledged) and pushes it now if the agent is connected. Returns the frame. */
export async function deliver(d: Deps, agentDid: string, frame: Frame, id = newId("itm")): Promise<Frame> {
  const full: Frame = { ...frame, id, created_at: now() };
  await d.db.run("INSERT INTO inbox (id, agent_did, frame, created_at) VALUES ($1, $2, $3, $4)", [id, agentDid, JSON.stringify(full), full.created_at]);
  const a = await d.db.first<{ connection_id: string | null }>("SELECT connection_id FROM agents WHERE did = $1", [agentDid]);
  await push(d, agentDid, a?.connection_id ?? null, full);
  return full;
}

/**
 * Closes the agent's socket. API Gateway cannot set a close code, so the last frame names it (WsError.close_code):
 * 4001 paused, 4003 unlinked, 4008 replaced by a newer socket.
 */
export async function closeSocket(d: Deps, agentDid: string, connectionId: string | null, code: 4001 | 4003 | 4008, error: string, message: string) {
  if (!connectionId || !d.ws) return;
  await push(d, agentDid, connectionId, { type: "error", error, message, close_code: code });
  await d.ws.close(connectionId).catch((e) => console.warn(`closing ${agentDid}'s socket failed`, e));
  await d.db.run("UPDATE agents SET connection_id = NULL WHERE did = $1 AND connection_id = $2", [agentDid, connectionId]);
}

/** Unacknowledged items, oldest first, at most 100, and whether more wait. */
export async function unacked(d: Deps, agentDid: string): Promise<{ items: Frame[]; more: boolean }> {
  const rows = await d.db.all<{ frame: string }>("SELECT frame FROM inbox WHERE agent_did = $1 AND acked_at IS NULL ORDER BY seq LIMIT 101", [agentDid]);
  return { items: rows.slice(0, 100).map((r) => JSON.parse(r.frame)), more: rows.length > 100 };
}

/** Marks items acknowledged; unknown ids are ignored. Owner messages record when the agent took them. */
export async function ack(d: Deps, agentDid: string, ids: unknown): Promise<void> {
  if (!Array.isArray(ids) || !ids.length || ids.length > 100 || ids.some((i) => typeof i !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(i))) {
    throw new HttpError(400, "bad_request", "ids must be 1 to 100 item ids");
  }
  const list = JSON.stringify(ids), t = now();
  await d.db.run("UPDATE inbox SET acked_at = $3 WHERE agent_did = $1 AND acked_at IS NULL AND id IN (SELECT jsonb_array_elements_text($2::jsonb))", [agentDid, list, t]);
  await d.db.run("UPDATE messages SET acked_at = $3 WHERE agent_did = $1 AND sender = 'owner' AND acked_at IS NULL AND id IN (SELECT jsonb_array_elements_text($2::jsonb))", [agentDid, list, t]);
}

/** The WebSocket routes, called by lambda.ts for API Gateway events. */
export async function wsEvent(d: Deps, event: any): Promise<{ statusCode: number; body?: string }> {
  const ctx = event.requestContext, id: string = ctx.connectionId;
  if (ctx.routeKey === "$connect") {
    let did: string;
    try {
      ({ did } = await verifySigned(d, { method: "GET", url: `wss://agents.${d.host}/`, headers: event.headers ?? {} }, { products: false }));
    } catch (e) {
      if (e instanceof HttpError) return { statusCode: 401, body: e.code };
      throw e;
    }
    const a = await d.db.first<{ connection_id: string | null }>("SELECT connection_id FROM agents WHERE did = $1 AND state <> 'unlinked'", [did]);
    if (!a) return { statusCode: 403, body: "not_paired" };
    // One socket per agent: the newer one replaces the older.
    if (a.connection_id && a.connection_id !== id) await closeSocket(d, did, a.connection_id, 4008, "replaced", "a newer socket from this agent replaced this one");
    await d.db.run("UPDATE agents SET connection_id = $2, last_seen_at = $3 WHERE did = $1", [did, id, now()]);
    return { statusCode: 200 };
  }
  if (ctx.routeKey === "$disconnect") {
    await d.db.run("UPDATE agents SET connection_id = NULL WHERE connection_id = $1", [id]);
    return { statusCode: 200 };
  }
  const a = await d.db.first<{ did: string }>("SELECT did FROM agents WHERE connection_id = $1 AND state <> 'unlinked'", [id]);
  if (!a) {
    await d.ws?.close(id).catch(() => {});
    return { statusCode: 403 };
  }
  let body: any = {};
  try { body = JSON.parse(event.body ?? "{}"); } catch { /* answered below */ }
  try {
    if (ctx.routeKey === "sync") {
      for (const f of (await unacked(d, a.did)).items) await push(d, a.did, id, f);
    } else if (ctx.routeKey === "ack") {
      await ack(d, a.did, body.ids);
    } else {
      await push(d, a.did, id, { type: "error", error: "bad_request", message: "actions are sync, ack and heartbeat" });
    }
  } catch (e) {
    if (!(e instanceof HttpError)) throw e;
    await push(d, a.did, id, { type: "error", error: e.code, message: e.message });
  }
  await d.db.run("UPDATE agents SET last_seen_at = $2 WHERE did = $1", [a.did, now()]);
  return { statusCode: 200 };
}
