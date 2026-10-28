import dns from "node:dns/promises";
import { afterEach, describe, expect, it, vi } from "vitest";
import { generateKeyPair } from "../src/sdk.ts";
import { clientIp, scheduled } from "../src/index.ts";
import { E, adopted, call, mockFetch, signed, write } from "./helpers.ts";
import { app } from "../src/index.ts";

afterEach(() => vi.restoreAllMocks());

describe("size limits (spec 4.1, 7.3)", () => {
  it("rejects an Entity Document over 64 KB", async () => {
    const kp = await generateKeyPair();
    const big = await signed(kp, "Big", { description: "a".repeat(70_000) });
    expect((await write("POST", "/adopt", kp.did, big)).status).toBe(413);
  });
  it("rejects a Record Entry over 16 KB", async () => {
    const { kp } = await adopted();
    const r = await write("POST", `/entities/${kp.did}/record`, kp.did, { entries: [{ pad: "a".repeat(17_000) }] });
    expect(r.status).toBe(413);
  });
});

describe("outbound fetches to writer-chosen hosts", () => {
  it("carry a timeout signal and refuse a body over 256 KB", async () => {
    const { kp } = await adopted();
    const spy = mockFetch({ "huge.example/.well-known/openentity.json": () => ({ eid: kp.did, pad: "x".repeat(300_000) }) });
    const r = await write("POST", `/entities/${kp.did}/aliases`, kp.did, { type: "domain", value: "did:web:huge.example" });
    expect(r.body.error).toBe("alias_proof_invalid");
    expect(spy.mock.calls[0][1]?.signal).toBeInstanceOf(AbortSignal);
  });
});

describe("observer accreditation", () => {
  it("keeps only https methodology URLs, since the site links them", async () => {
    const did = "did:web:evil-obs.example";
    for (let i = 0; i < 10; i++) {
      await E.db.run("INSERT INTO attestations (sha256, issuer, subject, claim_type, json, created, expires) VALUES ($1, $2, $3, 'identity', '{}', 'x', 'x')", [`sec${i}`, did, `did:key:z6Mksec${i}`]);
    }
    mockFetch({ "evil-obs.example/.well-known/openentity.json": () => ({ name: "Evil", extensions: { "openentity:observer": { methodology: "javascript:alert(1)" }, "openentity:trust_policy": { url: "https://evil-obs.example/policy" } } }) });
    await scheduled(E);
    const o = await E.db.first("SELECT methodology_url, trust_policy_url FROM observers WHERE did = $1", [did]);
    expect(o).toEqual({ methodology_url: null, trust_policy_url: "https://evil-obs.example/policy" });
  });
});

describe("browser agents and uniform guards", () => {
  it("answers the adopt preflight with the headers a write needs, and no credentials", async () => {
    const res = await app.request("https://openentity.org/v1/adopt", { method: "OPTIONS", headers: { origin: "https://agent.example", "access-control-request-method": "POST" } }, E);
    expect(res.status).toBe(204);
    const allow = (res.headers.get("access-control-allow-headers") ?? "").toLowerCase();
    expect(allow).toContain("x-oe-stamp");
    expect(allow).toContain("content-type");
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
    expect(res.headers.get("access-control-allow-credentials")).toBeNull();
  });
  it("checks the stamp before the body", async () => {
    expect((await call("POST", "/adopt", "{not json")).body.error).toBe("stamp_required");
  });
  it("reports verify timestamp as a status object", async () => {
    const { kp } = await adopted();
    const old = { spec: "openentity/1.0", type: "Withdrawal", eid: kp.did, declaration_version: "1.0", created: "2020-01-01T00:00:00Z", nonce: "n" };
    const t = (await call("POST", "/verify", old)).body.timestamp;
    expect(t).toMatchObject({ ok: false });
    expect(typeof t.reason).toBe("string");
  });
  it("answers GET /v1 as JSON", async () => {
    const res = await app.request("https://openentity.org/v1", {}, E);
    expect(res.headers.get("content-type")).toMatch(/json/);
  });
});

describe("SSRF guard on fetches to writer-chosen hosts", () => {
  const value = "eip155:8453:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432:7";
  const abiString = (s: string) => {
    const h = Array.from(new TextEncoder().encode(s), (b) => b.toString(16).padStart(2, "0")).join("");
    return "0x" + (32).toString(16).padStart(64, "0") + (h.length / 2).toString(16).padStart(64, "0") + h.padEnd(Math.ceil(h.length / 64) * 64, "0");
  };
  const bindVia = async (uri: string, dnsAnswers: Record<string, string> = {}) => {
    const { kp } = await adopted();
    const hits: string[] = [];
    mockFetch({
      "rpc.test": () => ({ jsonrpc: "2.0", id: 1, result: abiString(uri) }),
      "": (req) => { hits.push(req.url); return { services: [{ name: "DID", endpoint: kp.did }] }; },
    }, dnsAnswers);
    const r = await write("POST", `/entities/${kp.did}/aliases`, kp.did, { type: "erc8004", value });
    return { r, hits: hits.filter((u) => !u.includes("rpc.test")) };
  };
  it("does not follow a userinfo trick that hides an IP literal behind a host name", async () => {
    const { r, hits } = await bindVia("https://agents.example:80@127.0.0.1/reg.json");
    expect(hits).toEqual([]);
    expect(r.body.error).toBe("alias_proof_invalid");
  });
  it.each(["https://0x7f.1/r.json", "https://2130706433/r.json", "https://017700000001/r.json", "https://[::1]/r.json", "https://[::ffff:127.0.0.1]/r.json", "https://169.254.169.254/r.json"])("refuses the IP literal %s", async (uri) => {
    const { hits } = await bindVia(uri);
    expect(hits).toEqual([]);
  });
  it.each(["127.0.0.1", "169.254.169.254", "10.1.2.3", "100.64.0.1", "192.168.0.9", "::1", "fe80::1", "fd00::1", "::ffff:169.254.169.254"])("refuses a host name that resolves to %s (DNS rebinding to a private address)", async (address) => {
    const { r, hits } = await bindVia("https://rebind.example/r.json", { "rebind.example": address });
    expect(hits).toEqual([]);
    expect(r.body.error).toBe("alias_proof_invalid");
  });
  it("connects to the address it validated and never resolves the name a second time (DNS rebind window)", async () => {
    const { kp } = await adopted();
    const spy = mockFetch({ "rebind2.example/.well-known/openentity.json": () => ({ eid: kp.did }) });
    // Public on the first answer, private on every later one.
    const seen = vi.mocked(dns.lookup).getMockImplementation()!;
    let n = 0;
    vi.mocked(dns.lookup).mockImplementation((async (...a: any[]) => (n++ === 0 ? (seen as any)(...a) : [{ address: "169.254.169.254", family: 4 }])) as any);
    await write("POST", `/entities/${kp.did}/aliases`, kp.did, { type: "domain", value: "did:web:rebind2.example" });
    expect(spy.connected).toEqual(["93.184.216.34"]);
    expect(n).toBe(1);
  });
  it("still fetches a host name that resolves to a public address", async () => {
    const { r, hits } = await bindVia("https://agents.example/r.json");
    expect(hits).toEqual(["https://agents.example/r.json"]);
    expect(r.status).toBe(201);
  });
});

describe("per-IP limit key", () => {
  const ip = (viewer: string) => clientIp({ req: { header: (k: string) => (k === "cloudfront-viewer-address" ? viewer : undefined) } } as any);
  it("is the same for every address in one IPv6 /64, since a single host owns that whole block", () => {
    expect(ip("2001:db8:1:2:aaaa::1:443")).toBe(ip("2001:db8:1:2:bbbb:cccc:dddd:eeee:5000"));
    expect(ip("2001:db8:1:2::1:443")).not.toBe(ip("2001:db8:1:3::1:443"));
  });
  it("leaves IPv4 alone", () => expect(ip("203.0.113.9:5555")).toBe("203.0.113.9"));
});
