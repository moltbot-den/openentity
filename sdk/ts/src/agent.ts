// The agent side of the OpenEntity Account (docs/mobile/PLAN.md 8.1 to 8.4; contract: account/openapi.yaml, tag "Agent API").
// pair() links an agent's did:key to its owner; Owner messages the owner, reports status, asks approvals and receives commands.
// Every call is RFC 9421-signed by the agent's did:key (signRequest). No CAPTCHA, login, email or payment anywhere.
import { OpenEntityError } from "./errors.ts";
import { utf8, type KeyPair } from "./core.ts";
import { buildPresentation } from "./objects.ts";
import { signRequest } from "./httpsig.ts";
import { pairSas } from "./pair.ts";
import pkg from "../package.json" with { type: "json" };

/** A KeyPair, or anything that holds one as `kp` (Identity from "@openentity/sdk/node"). */
export type Signer = KeyPair | { kp: KeyPair };
/** A product key for tools that still need one (PLAN 8.4): issued for 30 days, scoped to the granted permissions. */
export interface BearerCredential { product: string; kind: "bearer"; key: string; expires_at: number }
export interface Paired { pairingId: string; ownerDid: string; permissions: string[]; credentials: BearerCredential[]; match: string[] }
/** What the owner's channel delivers: a message, a command (checkup, fix, pause, resume), an approval result or new permissions. */
export interface InboxItem { type: "message" | "command" | "approval.result" | "permissions"; id: string; created_at: number; [field: string]: unknown }
export type AgentState = "running" | "idle" | "blocked" | "error" | "done";

const ACCOUNT = "https://account.openentity.org";
const CODE = /^OE-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/;
const keyOf = (s: Signer): KeyPair => ("kp" in s ? s.kp : s);
const baseOf = (account?: string) => (account ?? ACCOUNT).replace(/\/+$/, "");
/** The account service's DID: did:web of its host (did:web:account.openentity.org, did:web:staging.account.openentity.org). */
const serviceDid = (base: string) => "did:web:" + new URL(base).host.replace(":", "%3A");
/** The agent WebSocket: wss://agents.<account host>/, trailing slash included (it is the signed @target-uri). */
const socketUrl = (base: string) => `wss://agents.${new URL(base).host}/`;
const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((ok) => {
    const t = setTimeout(ok, ms);
    signal?.addEventListener("abort", () => (clearTimeout(t), ok()), { once: true });
  });

/** One signed call to the Agent API. Errors carry the service's code, the HTTP status and, on 429, `retryAfter` seconds. */
async function agentCall(kp: KeyPair, base: string, method: string, path: string, body?: unknown): Promise<any> {
  const url = base + path;
  const bytes = body === undefined ? undefined : utf8(JSON.stringify(body));
  const headers: Record<string, string> = { accept: "application/json", ...(await signRequest({ method, url, body: bytes, privateKey: kp, did: kp.did })) };
  if (bytes) headers["content-type"] = "application/json";
  const r = await fetch(url, { method, headers, body: bytes as BodyInit | undefined, signal: AbortSignal.timeout(30_000) });
  const text = await r.text();
  if (r.ok) return text ? JSON.parse(text) : null;
  let code = "account_error", message = text.slice(0, 200);
  try {
    const e = JSON.parse(text);
    if (typeof e?.error === "string") [code, message] = [e.error, String(e.message ?? "")];
  } catch { /* not a JSON error body */ }
  const err = new OpenEntityError(code, `account ${r.status} for ${method} ${path}: ${message}`, r.status) as OpenEntityError & { retryAfter?: number };
  err.retryAfter = Number(r.headers.get("retry-after")) || undefined;
  throw err;
}

/**
 * Pair this agent with its owner (PLAN 8.1). `code` is the `OE-XXXX-XXXX` code the owner's app shows. Signs a Presentation
 * (audience = the account service DID, nonce = "pair:" + the code) into `POST /v1/pair`, checks that the service's match
 * items equal the ones computed here from this agent's own DID (else it refuses: a service must not be able to substitute
 * another agent), hands them to `onMatch` (default: prints `Match: ...`), then polls until the owner confirms, rejects or the
 * code expires.
 * Errors: `pairing_rejected`, `pairing_expired`, `verification_failed` (match mismatch) or the service's code (`code_unknown`,
 * `code_used`, `code_expired`, ...). Bearer credentials appear only in this result: store them (PLAN 8.4).
 */
export async function pair(code: string, o: {
  identity: Signer; framework?: string; sdk?: string; sdkVersion?: string; host?: string; account?: string;
  onMatch?: (names: string[]) => void | Promise<void>;
}): Promise<Paired> {
  const kp = keyOf(o.identity), base = baseOf(o.account);
  const c = String(code).trim().toUpperCase();
  if (!CODE.test(c)) throw new OpenEntityError("invalid_input", "the pairing code looks like OE-XXXX-XXXX");
  const match = pairSas(c, kp.did);
  // The nonce is "pair:" + the code: OEIS-1 nonces have at least 16 characters, so the bare code would fail verifyPresentation.
  const presentation = await buildPresentation(kp, { audience: serviceDid(base), nonce: `pair:${c}` });
  const claim = await agentCall(kp, base, "POST", "/v1/pair", {
    code: c, presentation, framework: o.framework ?? "other", sdk: o.sdk ?? "@openentity/sdk", sdk_version: o.sdkVersion ?? pkg.version, ...(o.host ? { host: o.host } : {}),
  });
  const sas = claim?.sas;
  if (sas?.version !== "pair-sas/1" || JSON.stringify(sas.names) !== JSON.stringify(match)) {
    throw new OpenEntityError("verification_failed", "the account service's match items differ from the ones this agent computes from its own DID; not pairing");
  }
  await (o.onMatch ?? ((n) => console.log(`Match: ${n.join(", ")}`)))(match);
  const every = Math.min(Math.max(Number(claim.poll_interval) || 2, 2), 60) * 1000; // the contract says 2; never faster
  const until = (Number(claim.expires_at) || Date.now() / 1000 + 600) + 30;
  for (;;) {
    await sleep(every);
    let s: any;
    try {
      s = await agentCall(kp, base, "GET", `/v1/pair/${encodeURIComponent(claim.pairing_id)}`);
    } catch (e: any) {
      // A blip during a wait of minutes is not a failed pairing: retry until the code's own expiry.
      if ((e.status === 429 || e.status >= 500 || e.status === undefined) && Date.now() / 1000 < until) {
        if (e.retryAfter) await sleep(e.retryAfter * 1000);
        continue;
      }
      throw e;
    }
    if (s.state === "confirmed") return { pairingId: claim.pairing_id, ownerDid: s.owner_did, permissions: s.permissions ?? [], credentials: s.credentials ?? [], match };
    if (s.state === "rejected" || s.state === "expired") throw new OpenEntityError(`pairing_${s.state}`, `the owner's app reports the pairing ${s.state}`);
    if (Date.now() / 1000 > until) throw new OpenEntityError("pairing_expired", "the pairing code expired before the owner confirmed");
  }
}

export interface Listener {
  close(): void;
  /** true after the service closed the socket with 4001 or sent a pause command, until a resume command arrives. */
  readonly paused: boolean;
  readonly mode: "socket" | "poll" | "closed";
}

/** The paired agent's channel to its owner. Construct it from the same key that paired; every call is RFC 9421-signed. */
export class Owner {
  readonly did: string;
  readonly account: string;
  readonly #kp: KeyPair;
  constructor(identity: Signer, o: { account?: string } = {}) {
    this.#kp = keyOf(identity);
    this.did = this.#kp.did;
    this.account = baseOf(o.account);
  }
  #call(method: string, path: string, body?: unknown) {
    return agentCall(this.#kp, this.account, method, path, body);
  }

  /** Message the owner (at most 4096 UTF-8 bytes; 60 an hour). `attachments` are upload ids from POST /v1/agent/uploads. */
  message(text: string, o: { attachments?: string[] } = {}): Promise<{ id: string }> {
    return this.#call("POST", "/v1/agent/messages", { text, ...(o.attachments?.length ? { attachments: o.attachments } : {}) });
  }

  /** Report what the agent is doing; the owner's app shows it (Live Activity). `progress` is 0 to 1. */
  async status(s: { state: AgentState; summary: string; progress?: number }): Promise<void> {
    await this.#call("POST", "/v1/agent/status", s.progress === undefined ? { state: s.state, summary: s.summary } : s);
  }

  /**
   * Ask the owner to approve something. The app labels it "Written by the agent" and no product accepts it as an approval of its
   * own: it is the owner's answer to this agent only. `expiresIn` is 60 to 600 seconds (default 600). With `wait`, polls every
   * 5 seconds until the owner decides or it expires, and returns the final state.
   */
  async askApproval(a: { title: string; summary: string; risk: "low" | "medium" | "high"; expiresIn?: number; details?: object }, o: { wait?: boolean } = {}): Promise<any> {
    let r = await this.#call("POST", "/v1/agent/approvals", { title: a.title, summary: a.summary, risk: a.risk, expires_in: a.expiresIn ?? 600, ...(a.details ? { details: a.details } : {}) });
    while (o.wait && r.state === "pending" && Date.now() / 1000 < r.expires_at + 10) {
      await sleep(5000);
      r = await this.#call("GET", `/v1/agent/approvals/${encodeURIComponent(r.id)}`);
    }
    return r;
  }

  /** Unacknowledged items, oldest first (up to 100), acknowledged on return unless `ack` is false. At most once every 15 seconds. */
  async inbox(o: { ack?: boolean } = {}): Promise<{ items: InboxItem[]; more: boolean }> {
    const r = await this.#call("GET", "/v1/agent/messages");
    if (o.ack !== false && r.items.length) await this.#call("POST", "/v1/agent/messages/ack", { ids: r.items.map((i: InboxItem) => i.id) });
    return r;
  }

  /** New product keys for the agent (PLAN 8.4); the old ones stay valid for 1 hour. Default: every product it holds a key for. */
  async renewCredentials(products?: string[]): Promise<BearerCredential[]> {
    return (await this.#call("POST", "/v1/agent/credentials/renew", products ? { products } : {})).credentials;
  }

  /**
   * Receive the owner's channel (PLAN 8.2): every item (commands, messages, approval results, permissions) goes to `handler`,
   * one at a time, and is acknowledged once the handler returns; a handler that throws leaves it for the next delivery. Holds
   * the WebSocket at wss://agents.<account host>/ (signed connect, heartbeat every 9 minutes, a fresh socket before the 2-hour
   * limit, backoff on drops). When no socket opens three times running, or there is no WebSocket, it polls
   * GET /v1/agent/messages every 15 seconds and tries the socket again after 10 minutes. The service names a close in its last
   * frame (`close_code`; API Gateway cannot set one), and a real close code counts too: 4001 means paused (`onPaused`): no
   * socket until the agent is resumed, which the polled resume command (or a GET that succeeds after 423) tells; 4003 (unlinked)
   * and 4008 (another socket of this agent took over) end it. `WebSocket` must send headers on the upgrade, as Node's built-in
   * one does; pass `WebSocket: null` to poll only.
   */
  onCommand(handler: (item: InboxItem) => void | Promise<void>, o: {
    onPaused?: () => void; onError?: (e: unknown) => void; WebSocket?: unknown; url?: string;
  } = {}): Listener {
    const kp = this.#kp, base = this.account, url = o.url ?? socketUrl(base);
    const WS = (o.WebSocket === undefined ? (globalThis as any).WebSocket : o.WebSocket) as any; // null: poll only
    const stop = new AbortController();
    const report = (e: unknown) => o.onError?.(e);
    const seen = new Set<string>();
    let ws: any, paused = false, mode: Listener["mode"] = WS ? "socket" : "poll", failures = 0, backoff = 1000;
    let queue: Promise<unknown> = Promise.resolve();
    const end = (e?: unknown) => {
      if (e) report(e);
      mode = "closed";
      stop.abort();
      ws?.close(1000);
    };
    /** Runs the handler; true means acknowledge. An item seen before (redelivered after a sync) is only acknowledged again. */
    const handle = async (item: InboxItem): Promise<boolean> => {
      if (seen.has(item.id)) return true;
      if (item.type === "command" && (item.command === "pause" || item.command === "resume")) paused = item.command === "pause";
      try {
        await handler(item);
      } catch (e) {
        report(e);
        return false;
      }
      seen.add(item.id);
      if (seen.size > 1000) seen.delete(seen.values().next().value!);
      return true;
    };
    const httpAck = (ids: string[]) => (ids.length ? agentCall(kp, base, "POST", "/v1/agent/messages/ack", { ids }).catch(report) : undefined);

    const connect = async () => {
      if (stop.signal.aborted) return;
      mode = "socket";
      let s: any;
      try {
        s = new WS(url, { headers: await signRequest({ method: "GET", url, privateKey: kp, did: kp.did }) });
      } catch (e) {
        report(e);
        return void poll();
      }
      ws = s;
      let openedAt = 0, renewing = false, closeAs = 0;
      const send = (frame: object) => s.readyState === 1 && s.send(JSON.stringify(frame));
      const heartbeat = setInterval(() => send({ action: "heartbeat" }), 540_000);
      const renew = setTimeout(() => ((renewing = true), s.close(1000)), 7_140_000); // a fresh socket before the service's 2-hour cut
      s.onopen = () => {
        openedAt = Date.now();
        failures = 0;
        send({ action: "sync" });
      };
      s.onmessage = (ev: { data: unknown }) => {
        let f: any;
        try {
          f = JSON.parse(String(ev.data));
        } catch { return; }
        if (f?.type === "error") {
          if (![4001, 4003, 4008].includes(f.close_code)) return report(new OpenEntityError(String(f.error), String(f.message)));
          closeAs = f.close_code; // the service's last frame before it closes: treat it as the close
          return s.close(1000);
        }
        if (typeof f?.id !== "string" || f.type === "heartbeat") return;
        queue = queue
          .then(async () => {
            if (await handle(f)) (s.readyState === 1 ? send({ action: "ack", ids: [f.id] }) : await httpAck([f.id]));
          })
          .catch(report);
      };
      s.onclose = (ev: { code: number }) => {
        clearInterval(heartbeat);
        clearTimeout(renew);
        if (stop.signal.aborted || ws !== s) return;
        const code = closeAs || ev.code;
        if (code === 4003) return end(new OpenEntityError("unlinked", "the owner unlinked this agent, or it is not paired"));
        if (code === 4008) return end(new OpenEntityError("replaced", "another socket of this agent took over"));
        if (code === 4001) {
          paused = true;
          o.onPaused?.();
          return void poll(); // no socket while paused; the fallback GET brings the resume command
        }
        if (!openedAt && ++failures >= 3) return void poll();
        if (openedAt && Date.now() - openedAt > 60_000) backoff = 1000; // a socket that held a while resets the backoff
        const wait = renewing ? 0 : backoff + Math.random() * 1000;
        backoff = Math.min(backoff * 2, 60_000);
        void sleep(wait, stop.signal).then(connect).catch(report);
      };
    };

    const poll = async () => {
      mode = "poll";
      const untilResumed = paused, retrySocketAt = Date.now() + 600_000;
      let refused = false;
      while (!stop.signal.aborted) {
        let wait = 15_000;
        try {
          const r = await agentCall(kp, base, "GET", "/v1/agent/messages");
          if (refused) paused = refused = false; // answered after agent_paused: resumed
          const done: string[] = [];
          for (const item of r.items) if (!stop.signal.aborted && (await handle(item))) done.push(item.id);
          await httpAck(done);
        } catch (e: any) {
          if (e.status === 403) return end(e); // not_paired: nothing will arrive
          if (e.code === "agent_paused") paused = refused = true;
          if (e.retryAfter) wait = e.retryAfter * 1000;
          report(e);
        }
        if (WS && !stop.signal.aborted && (untilResumed ? !paused : Date.now() >= retrySocketAt)) {
          failures = 0;
          return connect().catch(report);
        }
        await sleep(wait, stop.signal);
      }
    };

    void (WS ? connect() : poll()).catch(report);
    return { close: () => end(), get paused() { return paused; }, get mode() { return mode; } };
  }
}
