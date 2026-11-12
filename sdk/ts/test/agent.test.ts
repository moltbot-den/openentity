// pair() and Owner against an in-memory account service that checks every RFC 9421 signature. No network.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as oe from "../src/index.ts";

const BASE = "https://account.example", SERVICE = "did:web:account.example", SOCKET = "wss://agents.account.example/";
const kp = await oe.keyPairFromSeed(Uint8Array.from({ length: 32 }, (_, i) => i + 1)); // published throwaway seed, test-vectors/keys.json
const other = await oe.keyPairFromSeed(new Uint8Array(32).fill(9));
const CODE = "OE-7K4M-Q2XP";

type Req = { method: string; path: string; body: any };
type Route = (r: Req) => Response | { status?: number; json?: unknown; headers?: Record<string, string> };
let calls: Req[] = [];
const real = globalThis.fetch;

/** The fake service: verifies the signature (the signer must be this agent), records the call, answers from `routes`. */
function serve(routes: Record<string, Route>) {
  calls = [];
  globalThis.fetch = (async (url: string, init: RequestInit = {}) => {
    const u = new URL(url), method = init.method ?? "GET";
    const bytes = init.body ? (init.body as Uint8Array) : undefined;
    const v = await oe.verifyRequest({ method, url, headers: init.headers as Record<string, string>, body: bytes });
    expect(v.did).toBe(kp.did);
    const req = { method, path: u.pathname, body: bytes ? JSON.parse(new TextDecoder().decode(bytes)) : undefined };
    calls.push(req);
    const route = routes[`${method} ${u.pathname}`];
    if (!route) return new Response(JSON.stringify({ error: "not_found", message: "no route" }), { status: 404 });
    const r = route(req);
    if (r instanceof Response) return r;
    return new Response(r.json === undefined ? null : JSON.stringify(r.json), { status: r.status ?? 200, headers: r.headers });
  }) as typeof fetch;
}
afterEach(() => {
  globalThis.fetch = real;
  vi.useRealTimers();
});

/** Advance fake time until `p` settles. */
async function settle<T>(p: Promise<T>): Promise<T> {
  let done = false;
  p.then(() => (done = true), () => (done = true));
  for (let i = 0; !done && i < 2000; i++) await vi.advanceTimersByTimeAsync(1000);
  return p;
}

const claim = (did = kp.did) => ({
  status: 201,
  json: { pairing_id: "pr_1", sas: { version: "pair-sas/1", indexes: [0, 0, 0, 0], names: oe.pairSas(CODE, did) }, expires_at: Math.floor(Date.now() / 1000) + 600, poll_interval: 2 },
});

describe("pair()", () => {
  beforeEach(() => vi.useFakeTimers());

  it("claims with a signed Presentation, shows the locally computed match, polls until confirmed", async () => {
    const states = ["claimed", "claimed", "confirmed"];
    const credentials = [{ product: "did:web:moltbotden.com", kind: "bearer", key: "moltbotden_sk_test", expires_at: 1 }];
    serve({
      "POST /v1/pair": (r) => {
        expect(r.body).toMatchObject({ code: CODE, framework: "openclaw", sdk: "openentity-cli", sdk_version: "9.9.9", host: "box" });
        expect(r.body.presentation).toMatchObject({ type: "Presentation", eid: kp.did, audience: SERVICE, nonce: CODE });
        return claim();
      },
      "GET /v1/pair/pr_1": () => {
        const state = states.shift();
        return { json: { state, owner_did: state === "confirmed" ? "did:web:account.example:o:abc" : null, permissions: ["owner.message"], ...(state === "confirmed" ? { credentials } : {}) } };
      },
    });
    const shown: string[][] = [];
    const r = await settle(oe.pair(" oe-7k4m-q2xp ", {
      identity: { kp }, framework: "openclaw", sdk: "openentity-cli", sdkVersion: "9.9.9", host: "box", account: BASE + "/",
      onMatch: (names) => void shown.push(names),
    }));
    expect(shown).toEqual([["red shell", "olive tree", "purple moon", "coral owl"]]); // test-vectors/pair-sas-1, case 1
    expect(r).toEqual({ pairingId: "pr_1", ownerDid: "did:web:account.example:o:abc", permissions: ["owner.message"], credentials, match: shown[0] });
    expect(calls.map((c) => c.method)).toEqual(["POST", "GET", "GET", "GET"]);
    expect((await oe.verifyPresentation(calls[0].body.presentation, { audience: SERVICE, nonce: CODE })).errors.join()).toMatch(/nonce/); // see the ponytail note in agent.ts
  });

  it("refuses when the service's match items are not this agent's", async () => {
    serve({ "POST /v1/pair": () => claim(other.did) });
    const onMatch = vi.fn();
    const e = await settle(oe.pair(CODE, { identity: kp, onMatch, account: BASE })).catch((x) => x);
    expect([e.code, onMatch.mock.calls.length, calls.length]).toEqual(["verification_failed", 0, 1]);
  });

  it("rides out 429 and 5xx while waiting; rejected and expired end it", async () => {
    for (const end of ["rejected", "expired"]) {
      const answers: Route[] = [
        () => ({ status: 429, json: { error: "rate_limited", message: "slow" }, headers: { "retry-after": "3" } }),
        () => ({ status: 503, json: { error: "unavailable", message: "x" } }),
        () => ({ json: { state: end, owner_did: null, permissions: [] } }),
      ];
      serve({ "POST /v1/pair": () => claim(), "GET /v1/pair/pr_1": (r) => answers.shift()!(r) });
      const e = await settle(oe.pair(CODE, { identity: kp, account: BASE, onMatch: () => {} })).catch((x) => x);
      expect(e.code).toBe(`pairing_${end}`);
      expect(calls.length).toBe(4);
    }
  });

  it("passes the service's refusal through; checks the code locally first", async () => {
    serve({ "POST /v1/pair": () => ({ status: 409, json: { error: "code_used", message: "used" } }) });
    const e = await settle(oe.pair(CODE, { identity: kp, account: BASE })).catch((x) => x);
    expect([e.code, e.status]).toEqual(["code_used", 409]);
    const bad = await oe.pair("OE-ILOU-1234", { identity: kp, account: BASE }).catch((x) => x);
    expect([bad.code, calls.length]).toEqual(["invalid_input", 1]);
  });
});

describe("Owner", () => {
  const owner = new oe.Owner(kp, { account: BASE });

  it("message, status, renewCredentials: signed bodies as the contract shapes them", async () => {
    serve({
      "POST /v1/agent/messages": () => ({ status: 201, json: { id: "m1" } }),
      "POST /v1/agent/status": () => ({ status: 204 }),
      "POST /v1/agent/credentials/renew": () => ({ json: { credentials: [{ product: "did:web:securemyagent.ai", kind: "bearer", key: "sma_x", expires_at: 2 }] } }),
    });
    expect(await owner.message("hello")).toEqual({ id: "m1" });
    await owner.status({ state: "running", summary: "indexing" });
    await owner.status({ state: "done", summary: "finished", progress: 1 });
    expect((await owner.renewCredentials())[0].key).toBe("sma_x");
    expect(calls.map((c) => c.body)).toEqual([{ text: "hello" }, { state: "running", summary: "indexing" }, { state: "done", summary: "finished", progress: 1 }, {}]);
    expect(owner.did).toBe(kp.did);
  });

  it("errors carry the service code, the status and Retry-After", async () => {
    serve({
      "POST /v1/agent/messages": () => ({ status: 423, json: { error: "agent_paused", message: "paused" } }),
      "GET /v1/agent/messages": () => ({ status: 429, json: { error: "rate_limited", message: "15 s" }, headers: { "retry-after": "12" } }),
    });
    const e = await owner.message("x").catch((x) => x);
    expect([e instanceof oe.OpenEntityError, e.code, e.status]).toEqual([true, "agent_paused", 423]);
    const r = await owner.inbox().catch((x) => x);
    expect([r.code, r.retryAfter]).toEqual(["rate_limited", 12]);
  });

  it("inbox acknowledges what it returns unless ack is false", async () => {
    const items = [{ type: "message", id: "a", created_at: 1, text: "hi", attachments: [] }, { type: "command", id: "b", created_at: 2, command: "checkup", args: {} }];
    serve({ "GET /v1/agent/messages": () => ({ json: { items, more: false } }), "POST /v1/agent/messages/ack": () => ({ status: 204 }) });
    expect((await owner.inbox()).items).toEqual(items);
    expect(calls[1]).toEqual({ method: "POST", path: "/v1/agent/messages/ack", body: { ids: ["a", "b"] } });
    await owner.inbox({ ack: false });
    expect(calls.length).toBe(3);
  });

  it("askApproval writes the request and, with wait, polls until decided", async () => {
    vi.useFakeTimers();
    const states = ["pending", "approved"];
    const at = Math.floor(Date.now() / 1000);
    serve({
      "POST /v1/agent/approvals": () => ({ status: 201, json: { id: "ap1", state: "pending", expires_at: at + 120 } }),
      "GET /v1/agent/approvals/ap1": () => ({ json: { id: "ap1", state: states.shift(), expires_at: at + 120 } }),
    });
    const r = await settle(owner.askApproval({ title: "Deploy", summary: "Ship v2 to prod", risk: "high", expiresIn: 120 }, { wait: true }));
    expect(r.state).toBe("approved");
    expect(calls[0].body).toEqual({ title: "Deploy", summary: "Ship v2 to prod", risk: "high", expires_in: 120 });
    expect(calls.length).toBe(3);
  });
});

/** A WebSocket stand-in: records frames, lets the test open, push and close. */
class FakeWS {
  static all: FakeWS[] = [];
  readyState = 0;
  sent: any[] = [];
  onopen?: () => void;
  onmessage?: (e: { data: string }) => void;
  onclose?: (e: { code: number }) => void;
  url: string;
  init: { headers: Record<string, string> };
  constructor(url: string, init: { headers: Record<string, string> }) {
    this.url = url;
    this.init = init;
    FakeWS.all.push(this);
  }
  send(s: string) {
    this.sent.push(JSON.parse(s));
  }
  close(code = 1000) {
    if (this.readyState === 3) return;
    this.readyState = 3;
    this.onclose?.({ code });
  }
  open() {
    this.readyState = 1;
    this.onopen?.();
  }
  push(frame: object) {
    this.onmessage?.({ data: JSON.stringify(frame) });
  }
}
const last = () => FakeWS.all.at(-1)!;
const cmd = (id: string, command: string) => ({ type: "command", id, created_at: 1, command, args: {} });

describe("Owner.onCommand", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    FakeWS.all = [];
  });
  const owner = new oe.Owner(kp, { account: BASE });
  const tick = (ms = 0) => vi.advanceTimersByTimeAsync(ms);

  it("connects signed, syncs, hands each item over once, acks it, heartbeats and renews before 2 hours", async () => {
    const got: string[] = [];
    const l = owner.onCommand((i) => void got.push(i.id), { WebSocket: FakeWS });
    await tick();
    const s = last();
    expect(s.url).toBe(SOCKET);
    expect((await oe.verifyRequest({ method: "GET", url: SOCKET, headers: s.init.headers })).did).toBe(kp.did);
    s.open();
    expect(s.sent).toEqual([{ action: "sync" }]);
    s.push(cmd("c1", "checkup"));
    s.push(cmd("c1", "checkup")); // redelivered: acked again, not handled again
    s.push({ type: "heartbeat" });
    await tick();
    expect(got).toEqual(["c1"]);
    expect(s.sent.slice(1)).toEqual([{ action: "ack", ids: ["c1"] }, { action: "ack", ids: ["c1"] }]);
    await tick(540_000);
    expect(s.sent.at(-1)).toEqual({ action: "heartbeat" });
    await tick(7_140_000 - 540_000);
    await tick(10);
    expect([s.readyState, FakeWS.all.length]).toEqual([3, 2]);
    expect(l.mode).toBe("socket");
    l.close();
    expect(last().readyState).toBe(3);
    await tick(120_000);
    expect(FakeWS.all.length).toBe(2);
  });

  it("a handler that throws leaves the item unacknowledged", async () => {
    const onError = vi.fn();
    owner.onCommand(() => { throw new Error("busy"); }, { WebSocket: FakeWS, onError });
    await tick();
    last().open();
    last().push(cmd("c2", "fix"));
    await tick();
    expect(last().sent).toEqual([{ action: "sync" }]);
    expect(onError.mock.calls[0][0].message).toBe("busy");
  });

  it("4001 means paused and reconnects; resume clears it; 4003 ends it", async () => {
    const onPaused = vi.fn(), onError = vi.fn();
    const l = owner.onCommand(() => {}, { WebSocket: FakeWS, onPaused, onError });
    await tick();
    last().open();
    last().close(4001);
    expect([l.paused, onPaused.mock.calls.length]).toEqual([true, 1]);
    await tick(3000);
    expect(FakeWS.all.length).toBe(2);
    last().open();
    last().push(cmd("r1", "resume"));
    await tick();
    expect(l.paused).toBe(false);
    last().close(4003);
    await tick(120_000);
    expect([l.mode, FakeWS.all.length, onError.mock.calls[0][0].code]).toEqual(["closed", 2, "unlinked"]);
  });

  it("falls back to polling GET /v1/agent/messages every 15 seconds when no socket opens", async () => {
    let n = 0;
    serve({
      "GET /v1/agent/messages": () => ({ json: { items: n++ ? [] : [cmd("p1", "checkup")], more: false } }),
      "POST /v1/agent/messages/ack": () => ({ status: 204 }),
    });
    const got: string[] = [];
    const l = owner.onCommand((i) => void got.push(i.id), { WebSocket: FakeWS });
    for (let i = 0; i < 3; i++) {
      await tick(70_000);
      last().close(1006); // never opened
    }
    await tick();
    expect([l.mode, got]).toEqual(["poll", ["p1"]]);
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual(["GET /v1/agent/messages", "POST /v1/agent/messages/ack"]);
    expect(calls[1].body).toEqual({ ids: ["p1"] });
    await tick(14_000);
    expect(calls.length).toBe(2);
    await tick(1_000);
    expect(calls.length).toBe(3);
    l.close();
  });

  it("without a WebSocket it polls from the start, and stops on not_paired", async () => {
    serve({ "GET /v1/agent/messages": () => ({ status: 403, json: { error: "not_paired", message: "no" } }) });
    const onError = vi.fn();
    const l = owner.onCommand(() => {}, { WebSocket: null, onError });
    await tick();
    expect([l.mode, onError.mock.calls[0][0].code, calls.length]).toEqual(["closed", "not_paired", 1]);
  });
});
