// The end-to-end app loop (PLAN 15, "End-to-end smoke"). oneentity/scripts/e2e-app-loop.sh runs it from a checkout of
// main with the CLI built there (OE_CLI). It prints a pass/fail table and exits 1 on any failure. Not part of the suite.
//
// Staging (default): a test owner (@test.openentity.org) signs in and creates a key log with throwaway keys; the CLI pairs
// an agent; messages go both ways with a status report; a staging test product asks for an approval/2.0 decision and
// verifies it as a product would; a pause closes the socket with 4001, the agent gets 423 and the product feed shows it
// within 60 s; resume by step-up, unlink, delete the owner; the analytics check skips while the tool keys are missing.
// Every row the run made is deleted at the end. `--app-review` also proves the App Review path (it toggles staging's
// APP_REVIEW_OPEN and restores it), shows the 21-day alarm and reads production's value.
//
// Production (--production): an owner session and an agent already paired, supplied by the caller (no sign-in
// automation). OE_OWNER_TOKEN is an owner access token, or OE_OWNER_COOKIE_FILE holds a web session's refresh value
// (rotated and written back); OE_AGENT_HOME is the agent's OPENENTITY_HOME. Read-only checks, then one pause: every product
// must refuse the agent within 60 s; the owner resumes in the app (Face ID), and every product must take it back.
import { execFileSync, spawn } from "node:child_process";
import { createHash, createPrivateKey, generateKeyPairSync, randomBytes, randomUUID, sign as nodeSign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GetParametersCommand, SSMClient } from "@aws-sdk/client-ssm";
import { canonicalize, generateKeyPair, keyPairFromJwk, keyPairFromSeed, pairSas, payloadDigest, signRequest, verifyApproval, verifyKeyLog, type KeyPair } from "@openentity/sdk";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import { dataApiDb } from "../src/db.ts";
import { lowS } from "../src/keylog.ts";

const PROD = process.argv.includes("--production"), APP_REVIEW = process.argv.includes("--app-review");
const HOST = PROD ? "account.openentity.org" : "staging.account.openentity.org", BASE = `https://${HOST}`, WSS = `wss://agents.${HOST}/`, SERVICE = `did:web:${HOST}`;
const CLI = process.env.OE_CLI ?? new URL("../../cli/dist/cli.js", import.meta.url).pathname;
const LIMIT = 60; // seconds: PLAN 8.3, a pause is enforced everywhere within a minute
const aws = (...a: string[]) => execFileSync("aws", [...a, "--region", "us-east-1", "--output", "json"], { encoding: "utf8" });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const now = () => Math.floor(Date.now() / 1000);

// ---------------------------------------------------------------- the table
type Result = "PASS" | "FAIL" | "SKIP";
const rows: { step: string; result: Result; detail: string; seconds: string }[] = [];
class Skip extends Error {}
let broken = false;
/** Runs a step unless an earlier one failed (`always` runs anyway); its return value is the detail column. */
async function step(name: string, fn: () => Promise<string>, always = false): Promise<void> {
  if (broken && !always) return void rows.push({ step: name, result: "SKIP", detail: "not run: an earlier step failed", seconds: "" });
  const t = Date.now();
  try {
    rows.push({ step: name, result: "PASS", detail: await fn(), seconds: ((Date.now() - t) / 1000).toFixed(1) });
  } catch (e) {
    const skip = e instanceof Skip;
    rows.push({ step: name, result: skip ? "SKIP" : "FAIL", detail: (e as Error).message.replace(/\s+/g, " ").slice(0, 300), seconds: ((Date.now() - t) / 1000).toFixed(1) });
    if (!skip) broken = true;
  }
}
const must = (ok: unknown, what: string) => { if (!ok) throw new Error(what); };

// ---------------------------------------------------------------- HTTP
async function call(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
  const r = await fetch(`${BASE}${path}`, { method, headers: { "content-type": "application/json", ...headers }, body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body), redirect: "manual" });
  const text = await r.text();
  let json: any = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: r.status, body: json, text, headers: r.headers };
}
const ok = async (p: Promise<{ status: number; body: any; text: string }>, what: string) => {
  const r = await p;
  if (r.status < 200 || r.status > 299) throw new Error(`${what}: ${r.status} ${r.text.slice(0, 200)}`);
  return r.body;
};
const agentCall = async (kp: KeyPair, method: string, path: string, body?: unknown) => {
  const raw = body === undefined ? undefined : JSON.stringify(body);
  return call(method, path, raw, await signRequest({ method, url: `${BASE}${path}`, body: raw ? new TextEncoder().encode(raw) : undefined, privateKey: kp, did: kp.did }));
};
/** Polls `probe` every 2 s until it holds, at most `limit` seconds; returns the seconds it took. */
async function within(limit: number, what: string, probe: () => Promise<boolean>): Promise<number> {
  const t = Date.now();
  for (;;) {
    if (await probe()) return (Date.now() - t) / 1000;
    if (Date.now() - t > limit * 1000) throw new Error(`${what}: not within ${limit} s`);
    await sleep(2000);
  }
}

// ---------------------------------------------------------------- keys and approvals
const p256 = () => {
  const k = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const { x, y } = k.publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const kid = createHash("sha256").update(`{"crv":"P-256","kty":"EC","x":"${x}","y":"${y}"}`).digest("base64url");
  const sign = (data: string | Uint8Array) => Buffer.from(lowS(new Uint8Array(nodeSign("sha256", Buffer.from(data), { key: k.privateKey, dsaEncoding: "ieee-p1363" })))).toString("base64url");
  return { x, y, kid, jwk: { kty: "EC" as const, crv: "P-256" as const, x, y }, sign };
};
type Approver = ReturnType<typeof p256>;
/** An approval/2.0 by a device approver over a request (verifier, owner, request id, payload digest, expiry). */
const approve = (a: Approver, req: any, decision = "approve") => Buffer.from(JSON.stringify({
  version: "approval/2.0", verifier_did: req.verifier_did, owner_did: req.owner_did, request_id: req.request_id, payload_digest: req.payload_digest, decision, expires_at: req.expires_at,
  device_id: a.kid, form: "p256", signature: a.sign(["approval/2.0", req.verifier_did, req.owner_did, req.request_id, req.payload_digest, decision, String(req.expires_at)].join("|")),
})).toString("base64url");
const base32 = (h: Buffer) => {
  const A = "abcdefghijklmnopqrstuvwxyz234567";
  let out = "", bits = 0, value = 0;
  for (const x of h) { value = (value << 8) | x; bits += 8; while (bits >= 5) out += A[(value >> (bits -= 5)) & 31]; value &= (1 << bits) - 1; }
  return bits ? out + A[(value << (5 - bits)) & 31] : out;
};

// ---------------------------------------------------------------- the CLI, built from main
function cli(home: string, args: string[], o: { onLine?: (line: string) => void } = {}): Promise<{ code: number; out: string }> {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [CLI, ...args], { env: { ...process.env, OPENENTITY_HOME: home, OPENENTITY_ACCOUNT: BASE } });
    let out = "";
    const take = (b: Buffer) => { out += b; for (const l of String(b).split("\n")) if (l.trim()) o.onLine?.(l); };
    p.stdout.on("data", take);
    p.stderr.on("data", take);
    p.on("close", (code) => resolve({ code: code ?? 1, out }));
  });
}
/** An agent home the CLI loads without adopting: no registry entity is created for a test agent. */
async function agentHome(): Promise<{ home: string; kp: KeyPair }> {
  const home = mkdtempSync(join(tmpdir(), "oe-e2e-agent-")), kp = await generateKeyPair(), dir = join(home, kp.did);
  mkdirSync(dir, { mode: 0o700 });
  writeFileSync(join(dir, "key"), JSON.stringify(kp.privateJwk), { mode: 0o600 });
  writeFileSync(join(dir, "entity.json"), JSON.stringify({ id: kp.did, name: "e2e app loop agent" }));
  writeFileSync(join(dir, "state.json"), JSON.stringify({ registry: "https://openentity.org", docSeq: 0, recordPushed: 0 }));
  writeFileSync(join(home, "current"), kp.did + "\n");
  return { home, kp };
}

// ---------------------------------------------------------------- staging
async function staging() {
  const outputs = JSON.parse(aws("cloudformation", "describe-stacks", "--stack-name", "OpenEntityAccountStaging")).Stacks[0].Outputs;
  const out = (k: string) => outputs.find((o: any) => o.OutputKey === k).OutputValue;
  const db = dataApiDb({ resourceArn: out("DbClusterArn"), secretArn: out("DbSecretArn"), database: "account" });
  const ssm = new SSMClient({ region: "us-east-1" });
  const seeds = await ssm.send(new GetParametersCommand({ Names: ["ass", "sma"].map((n) => `/openentity/account/test_product_${n}_seed_staging`), WithDecryption: true }));
  const seed = (n: string) => new Uint8Array(Buffer.from(seeds.Parameters!.find((p) => p.Name!.includes(`_${n}_`))!.Value!, "base64url"));
  const testProduct = (n: string) => `did:web:${HOST}:test-products:${n}`;
  const started = Date.now();

  const email = `e2e-${randomUUID().slice(0, 8)}@test.openentity.org`, install = randomUUID();
  const client = { platform: "ios", install_id: install, app_version: "e2e", device_model: "e2e-app-loop" };
  let auth: Record<string, string> = {}, accountId = "", ownerId = "", ownerDid = "";
  const approver = p256();
  const { home, kp } = await agentHome();
  let socket: WebSocket | undefined;
  try {
    await step("1a. owner signs in (test sign-in, @test.openentity.org)", async () => {
      const t = await ok(call("POST", "/v1/auth/test-idp", { kind: "email", email }), "test-idp");
      const s = await ok(call("POST", "/v1/auth/email/verify", { challenge_id: t.challenge_id, code: t.code, client }), "email verify");
      accountId = s.account.id;
      auth = { authorization: `Bearer ${s.access_token}` };
      return `${accountId} (${email})`;
    });
    await step("1b. key log genesis with throwaway keys", async () => {
      // The root passkey: a software authenticator answers the registration (attestation none, user verified).
      const opts = await ok(call("POST", "/v1/auth/passkey/options", { mode: "register", client }, auth), "passkey options");
      const root = p256(), credId = randomBytes(16);
      const cose = isoCBOR.encode(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(root.x, "base64url")], [-3, Buffer.from(root.y, "base64url")]]));
      const authData = Buffer.concat([createHash("sha256").update(HOST).digest(), Buffer.from([0x45, 0, 0, 0, 0]), Buffer.alloc(16), Buffer.from([0, 16]), credId, Buffer.from(cose)]);
      const clientData = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge: opts.options.challenge, origin: BASE, crossOrigin: false }));
      const attObj = isoCBOR.encode(new Map<string, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", new Uint8Array(authData)]]) as any);
      const reg = await ok(call("POST", "/v1/auth/passkey/verify", { challenge_id: opts.challenge_id, client, response: {
        id: credId.toString("base64url"), rawId: credId.toString("base64url"), type: "public-key", clientExtensionResults: {},
        response: { clientDataJSON: clientData.toString("base64url"), attestationObject: Buffer.from(attObj).toString("base64url"), transports: ["internal"] },
      } }, auth), "passkey verify");
      const unsigned = { v: 1, seq: 1, prev: null, op: "genesis", ts: now(), body: { root: reg.credential, approver: { kid: approver.kid, type: "p256", jwk: approver.jwk, label: "e2e", platform: "ios", key_storage: "secure_enclave", attestation: { type: "none", verified: false } } } };
      const line = canonicalize({ ...unsigned, auth: { kid: approver.kid, form: "p256", signature: approver.sign(canonicalize(unsigned)) } });
      ownerId = base32(createHash("sha256").update(line).digest());
      await ok(call("POST", `/o/${ownerId}/log`, { line }, auth), "genesis");
      ownerDid = `did:web:${HOST}:o:${ownerId}`;
      return ownerDid;
    });

    await step("2. pair an agent with the CLI built from main", async () => {
      const pairing = await ok(call("POST", "/v1/pairings", undefined, auth), "pairing code");
      let match = "";
      const run = cli(home, ["pair", pairing.code, "--framework", "e2e"], { onLine: (l) => { if (l.startsWith("Match:")) match = l.slice(6).trim(); } });
      await within(30, "the agent's claim", async () => (await ok(call("GET", `/v1/pairings/${pairing.id}`, undefined, auth), "pairing")).state === "claimed");
      const permissions = ["owner.approval", "owner.message", "owner.status"];
      const detail = await ok(call("GET", `/v1/pairings/${pairing.id}?permissions=${permissions.join(",")}`, undefined, auth), "pairing detail");
      must(detail.agent.did === kp.did, `claimed by ${detail.agent.did}, not the agent`);
      must(detail.sas.names.join() === pairSas(pairing.code, kp.did).join(), "the match string differs from pair-sas/1");
      await ok(call("POST", `/v1/pairings/${pairing.id}/confirm`, { permissions }, { ...auth, "x-oe-approval": approve(approver, detail.approval_request) }), "confirm");
      const r = await run;
      must(r.code === 0, `the CLI exited ${r.code}: ${r.out.slice(-300)}`);
      must(match === detail.sas.names.join(", "), `the CLI showed "${match}", the app "${detail.sas.names.join(", ")}"`);
      return `${kp.did}; match "${match}" on both sides`;
    });

    await step("3. messages both ways and a status report", async () => {
      must((await cli(home, ["owner", "message", "hello from the agent"])).code === 0, "the CLI could not message the owner");
      await ok(call("POST", `/v1/agents/${encodeURIComponent(kp.did)}/messages`, { text: "hello from the owner" }, auth), "owner message");
      const inbox = await cli(home, ["owner", "inbox", "--json"]);
      must(inbox.code === 0 && inbox.out.includes("hello from the owner"), `the agent's inbox: ${inbox.out.slice(-200)}`);
      must((await cli(home, ["owner", "status", "running", "e2e app loop", "--progress", "0.5"])).code === 0, "the CLI could not report a status");
      const thread = (await ok(call("GET", `/v1/agents/${encodeURIComponent(kp.did)}/messages`, undefined, auth), "thread")).messages;
      must(thread.some((m: any) => m.from === "agent" && m.text === "hello from the agent"), "the owner's thread lacks the agent's message");
      const view = await ok(call("GET", `/v1/agents/${encodeURIComponent(kp.did)}`, undefined, auth), "agent view");
      must(view.status?.summary === "e2e app loop" && view.status?.progress === 0.5, `status ${JSON.stringify(view.status)}`);
      return "agent to owner, owner to agent, status running 0.5";
    });

    await step("4. approval/2.0 decision asked by a test product, verified as the product would", async () => {
      const did = testProduct("ass"), payload = { action: "vault.read", path: "staging/e2e" };
      const seg = (v: object) => Buffer.from(JSON.stringify(v)).toString("base64url");
      const input = `${seg({ alg: "EdDSA", kid: `${did}#key-1`, typ: "oe-approval-request+jwt" })}.${seg({ iss: did, aud: SERVICE, iat: now(), exp: now() + 600, request_id: `e2e_${randomUUID().slice(0, 8)}`, owner_did: ownerDid, payload, payload_digest: payloadDigest(payload), return_url: "https://agentsecretstore.com/approve/return" })}`;
      const key = createPrivateKey({ key: (await keyPairFromSeed(seed("ass"))).privateJwk as any, format: "jwk" });
      const check = await ok(call("POST", "/v1/approve/check", { request: `${input}.${nodeSign(null, Buffer.from(input), key).toString("base64url")}` }), "approve check");
      const approval = JSON.parse(Buffer.from(approve(approver, check), "base64url").toString());
      // The product's side: the owner's log from the account, verified locally, then the approval against it.
      const log = await fetch(`${BASE}/o/${ownerId}/log`);
      const lines = (await log.text()).split("\n").filter(Boolean), seen = log.headers.get("x-oe-first-seen-at")!.split(",").map(Number);
      const did_json = await (await fetch(`${BASE}/.well-known/did.json`)).json();
      const serviceKeys = did_json.verificationMethod.filter((m: any) => m.publicKeyJwk?.crv === "P-256").map((m: any) => m.publicKeyJwk);
      const log_ = verifyKeyLog(ownerDid, lines, seen, { rpId: HOST, serviceKeys });
      if (!log_.ok) throw new Error(`the key log does not verify: ${log_.error} at ${log_.seq}`);
      const v = verifyApproval(approval, { keyLog: log_.state, verifierDid: check.verifier_did, ownerDid, requestId: check.request_id, payloadDigest: payloadDigest(payload), rpId: HOST });
      must(v.ok, `verifyApproval: ${JSON.stringify(v)}`);
      return `verifier ${check.verifier_did} (test product ass), approved by ${approver.kid.slice(0, 12)}...`;
    });

    await step("5. pause: close 4001, 423 to the agent, paused in the product feed, within 60 s", async () => {
      const frames: any[] = [];
      socket = new WebSocket(WSS, { headers: await signRequest({ method: "GET", url: WSS, privateKey: kp, did: kp.did }) } as any);
      const closed = new Promise<void>((r) => socket!.addEventListener("close", () => r()));
      socket.addEventListener("message", (e) => frames.push(JSON.parse(String(e.data))));
      await new Promise<void>((res, rej) => { socket!.addEventListener("open", () => res()); socket!.addEventListener("error", () => rej(new Error("WebSocket upgrade refused"))); });
      const paused = Date.now();
      await ok(call("POST", `/v1/agents/${encodeURIComponent(kp.did)}/pause`, { source: "app" }, auth), "pause");
      const sock = await within(LIMIT, "close_code 4001", async () => frames.some((f) => f.close_code === 4001));
      await within(LIMIT, "the socket closing", async () => Promise.race([closed.then(() => true), sleep(100).then(() => false)]));
      const refused = await within(LIMIT, "423 agent_paused", async () => (await agentCall(kp, "POST", "/v1/agent/messages", { text: "still here" })).status === 423);
      // The products' poll path: GET /v1/paused, signed by a staging test product, as each product polls it.
      const sma = await keyPairFromSeed(seed("sma"));
      const feed = await within(LIMIT, "the paused feed", async () => {
        const url = `${BASE}/v1/paused`;
        const r = await call("GET", "/v1/paused", undefined, await signRequest({ method: "GET", url, privateKey: sma, did: `${testProduct("sma")}#key-1` }));
        return r.status === 200 && JSON.stringify(r.body).includes(kp.did) && JSON.stringify(r.body).includes("paused");
      });
      return `4001 after ${sock.toFixed(1)} s, 423 after ${refused.toFixed(1)} s, feed after ${feed.toFixed(1)} s (from the pause at ${new Date(paused).toISOString().slice(11, 19)})`;
    });

    await step("6a. resume by step-up", async () => {
      const req = await ok(call("POST", "/v1/step-up", { action: "agent.resume", params: { agent_did: kp.did } }, auth), "step-up");
      const r = await ok(call("POST", `/v1/agents/${encodeURIComponent(kp.did)}/resume`, undefined, { ...auth, "x-oe-approval": approve(approver, req) }), "resume");
      must(r.state === "active", `state ${r.state}`);
      must((await agentCall(kp, "GET", "/v1/agent")).status === 200, "the agent is still refused after resume");
      return "active; the agent is served again";
    });
    await step("6b. unlink", async () => {
      must((await call("DELETE", `/v1/agents/${encodeURIComponent(kp.did)}`, undefined, auth)).status === 204, "unlink");
      must((await agentCall(kp, "GET", "/v1/agent")).body?.error === "not_paired", "the agent still acts after unlink");
      return "the agent gets 403 not_paired";
    });
    await step("6c. delete the owner (step-up account.delete)", async () => {
      const req = await ok(call("POST", "/v1/step-up", { action: "account.delete", params: {} }, auth), "step-up");
      await ok(call("POST", "/v1/account/delete", undefined, { ...auth, "x-oe-approval": approve(approver, req) }), "delete");
      must((await call("GET", "/v1/me", undefined, auth)).status === 401, "the deleted owner's token still works");
      return "deleted; the session is gone";
    });

    await step("7. analytics arrival", async () => {
      const names = ["amplitude_api_key", "posthog_key", "ga4_measurement_id", "ga4_api_secret"].map((t) => `/openentity/account/analytics_${t}_staging`);
      const have = (await ssm.send(new GetParametersCommand({ Names: names }))).Parameters?.map((p) => p.Name!) ?? [];
      const fn = JSON.parse(aws("lambda", "list-functions")).Functions.map((f: any) => f.FunctionName).find((n: string) => n.startsWith("OpenEntityAccountStaging-AnalyticsFn"));
      const lines: string[] = JSON.parse(aws("logs", "filter-log-events", "--log-group-name", `/aws/lambda/${fn}`, "--start-time", String(started))).events.map((e: any) => e.message);
      must(!lines.some((m) => /Invoke Error|Task timed out/.test(m)), "the forwarder failed during the run");
      const missing = names.filter((n) => !have.includes(n)).map((n) => n.split("/").pop());
      if (missing.length) throw new Skip(`tool keys missing (${missing.join(", ")}); the forwarder took this run's events without an error`);
      return "every tool configured; the forwarder delivered without an error";
    });
  } finally {
    socket?.close();
    rmSync(home, { recursive: true, force: true });
    await step("leaves no rows behind", async () => {
      const ids: Record<string, string> = { account_id: accountId, agent_did: kp.did, owner_did: ownerDid, owner_id: ownerId };
      const cols = await db.all<{ table_name: string; column_name: string }>(
        "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public' AND column_name IN ('account_id', 'agent_did', 'owner_did', 'owner_id')");
      const targets = cols.filter((c) => ids[c.column_name]);
      if (accountId) await db.run("DELETE FROM refresh_tokens WHERE session_id IN (SELECT id FROM sessions WHERE account_id = $1)", [accountId]);
      for (const c of targets.filter((c) => c.table_name !== "accounts")) await db.run(`DELETE FROM ${c.table_name} WHERE ${c.column_name} = $1`, [ids[c.column_name]]);
      if (accountId) await db.run("DELETE FROM accounts WHERE id = $1", [accountId]);
      await db.run("DELETE FROM rate_events WHERE key LIKE $1", [`%${kp.did}%`]);
      await db.run("DELETE FROM email_codes WHERE email = $1", [email]);
      await db.run("DELETE FROM auth_nonces WHERE install_id = $1", [install]);
      let left = 0;
      for (const c of targets) left += Number((await db.first<{ n: number }>(`SELECT count(*) AS n FROM ${c.table_name} WHERE ${c.column_name} = $1`, [ids[c.column_name]]))!.n);
      if (accountId) left += Number((await db.first<{ n: number }>("SELECT count(*) AS n FROM accounts WHERE id = $1", [accountId]))!.n);
      must(left === 0, `${left} rows remain`);
      return `0 rows in ${targets.length + 1} tables`;
    }, true);
  }
  if (APP_REVIEW) await appReview(db);
}

// ---------------------------------------------------------------- App Review (staging, --app-review)
async function appReview(db: ReturnType<typeof dataApiDb>) {
  const scripts = new URL("../../scripts/app-review.sh", import.meta.url).pathname;
  const ssm = new SSMClient({ region: "us-east-1" });
  const p = await ssm.send(new GetParametersCommand({ Names: ["app_review_email", "app_review_code", "app_review_open_staging", "app_review_open_prod"].map((n) => `/openentity/account/${n}`), WithDecryption: true }));
  const param = (n: string) => p.Parameters?.find((x) => x.Name === `/openentity/account/${n}`)?.Value;
  const email = param("app_review_email"), code = param("app_review_code"), before = param("app_review_open_staging") ?? "0";
  const fn = JSON.parse(aws("cloudformation", "describe-stacks", "--stack-name", "OpenEntityAccountStaging")).Stacks[0].Outputs.find((o: any) => o.OutputKey === "FunctionName").OutputValue;
  const group = JSON.parse(aws("lambda", "get-function-configuration", "--function-name", fn)).LoggingConfig.LogGroup; // the stack's own log group
  const toggle = (state: "on" | "off") => { execFileSync("bash", [scripts, state, "staging"], { encoding: "utf8" }); aws("lambda", "wait", "function-updated", "--function-name", fn); };
  const attempt = async () => {
    const c = { platform: "ios", install_id: randomUUID() };
    const s = await call("POST", "/v1/auth/email/start", { email, client: c });
    must(s.status === 202, `email start for the demo address: ${s.status} ${s.text.slice(0, 120)}`);
    return call("POST", "/v1/auth/email/verify", { challenge_id: s.body.challenge_id, code, client: c });
  };
  let reviewAccount = "";
  try {
    await step("App Review: off refuses the demo code", async () => {
      must(email && code, "app_review_email or app_review_code is not set in SSM");
      toggle("off");
      const r = await attempt();
      must(r.status >= 400, `the demo code was accepted with APP_REVIEW_OPEN off (${r.status})`);
      return `${r.status} ${r.body?.error}`;
    });
    await step("App Review: on accepts it and logs app_review_sign_in", async () => {
      const t = Date.now();
      toggle("on");
      const r = await attempt();
      must(r.status === 200, `the demo code was refused with APP_REVIEW_OPEN on (${r.status} ${r.text.slice(0, 120)})`);
      reviewAccount = r.body.account.id;
      const seen = await within(LIMIT, "the app_review_sign_in log line", async () => JSON.parse(aws("logs", "filter-log-events", "--log-group-name", group, "--start-time", String(t), "--filter-pattern", '"app_review_sign_in"')).events.length > 0);
      return `200, logged after ${seen.toFixed(1)} s`;
    });
  } finally {
    // Leave staging as it was (off unless it was on), and the demo account without sessions.
    toggle(Number(before) > 0 ? "on" : "off");
    if (Number(before) > 0) execFileSync("aws", ["ssm", "put-parameter", "--region", "us-east-1", "--name", "/openentity/account/app_review_open_staging", "--type", "String", "--value", before, "--overwrite"]);
    if (reviewAccount) await db.run("UPDATE sessions SET revoked_at = $2, revoke_reason = 'e2e' WHERE account_id = $1 AND revoked_at IS NULL", [reviewAccount, now()]);
    // The demo address's spent codes: they would count against its 3 codes an hour on the next run.
    await db.run("DELETE FROM email_codes WHERE email = $1", [email]);
  }
  await step("App Review: the 21-day alarm exists in both stages", async () => {
    const alarms = JSON.parse(aws("cloudwatch", "describe-alarms", "--alarm-name-prefix", "OpenEntityAccount")).MetricAlarms.filter((a: any) => a.MetricName === "AppReviewOpenDays");
    must(alarms.length === 2 && alarms.every((a: any) => a.Threshold === 21 && a.AlarmActions.length === 1), `alarms: ${JSON.stringify(alarms.map((a: any) => [a.AlarmName, a.Threshold]))}`);
    return alarms.map((a: any) => `${a.AlarmName.split("-")[0]}: ${a.Threshold} days, ${a.StateValue}`).join("; ");
  }, true);
  await step("App Review: production app_review_open is off", async () => {
    const v = param("app_review_open_prod") ?? "absent";
    must(v === "absent" || Number(v) === 0, `production app_review_open_prod is ${v}`);
    return `app_review_open_prod = ${v}`;
  }, true);
}

// ---------------------------------------------------------------- production (--production)
/**
 * Each product's probe: its read-only "who am I" call with the agent's key, which the product refuses with 423
 * agent_paused while the owner has paused the agent (each one traced from the route to its pause check).
 */
const PROBES: { product: string; name: string; url: string; header: (key: string) => Record<string, string> }[] = [
  { product: "did:web:moltbotden.com", name: "Moltbot Den", url: "https://api.moltbotden.com/agents/me", header: (k) => ({ "x-api-key": k }) },
  { product: "did:web:securemyagent.ai", name: "Secure My Agent", url: "https://api.securemyagent.ai/v1/agents/me", header: (k) => ({ authorization: `Bearer ${k}` }) },
  { product: "did:web:api.agentsecretstore.com", name: "Agent Secret Store", url: "https://api.agentsecretstore.com/v1/agents/whoami", header: (k) => ({ authorization: `Bearer ${k}` }) },
  { product: "did:web:api.clawgrc.com", name: "ClawGRC", url: "https://api.clawgrc.com/api/v1/auth/me", header: (k) => ({ "x-api-key": k }) },
];

async function production() {
  const agentDir = process.env.OE_AGENT_HOME ?? "";
  must(agentDir, "set OE_AGENT_HOME to the paired agent's OPENENTITY_HOME");
  const did = readFileSync(join(agentDir, "current"), "utf8").trim();
  const kp = await keyPairFromJwk(JSON.parse(readFileSync(join(agentDir, did, "key"), "utf8")));
  const ownerAuth = async (): Promise<Record<string, string>> => {
    if (process.env.OE_OWNER_TOKEN) return { authorization: `Bearer ${process.env.OE_OWNER_TOKEN}` };
    const file = process.env.OE_OWNER_COOKIE_FILE ?? "";
    must(file, "set OE_OWNER_TOKEN, or OE_OWNER_COOKIE_FILE with a web session's refresh value");
    const r = await call("POST", "/v1/token", { grant_type: "refresh_token", audience: [SERVICE] }, { cookie: `__Host-oe_session=${readFileSync(file, "utf8").trim()}`, origin: BASE });
    must(r.status === 200, `the owner's web session did not refresh: ${r.status} ${r.text.slice(0, 120)}`);
    const next = (r.headers.getSetCookie?.() ?? []).find((c) => c.startsWith("__Host-oe_session="));
    if (next) writeFileSync(file, next.split(";")[0].split("=")[1] + "\n", { mode: 0o600 }); // rotated: the old value is spent
    return { authorization: `Bearer ${r.body.tokens[0].access_token}` };
  };
  let auth: Record<string, string> = {};
  const keys = new Map<string, string>();
  const probe = async (p: (typeof PROBES)[number]) => (await fetch(p.url, { headers: p.header(keys.get(p.product)!) })).status;

  await step("read-only: the service, the owner and the agent", async () => {
    auth = await ownerAuth();
    must((await ok(call("GET", "/v1/health"), "health")).ok, "health");
    const me = await ok(call("GET", "/v1/me", undefined, auth), "me");
    const agent = (await ok(call("GET", "/v1/agents", undefined, auth), "agents")).agents.find((a: any) => a.did === kp.did);
    must(agent && agent.state === "active", `the owner does not hold ${kp.did} active`);
    must((await agentCall(kp, "GET", "/v1/agent")).status === 200, "the agent is not served");
    return `owner ${me.owner_did}; agent ${kp.did} active on ${agent.products.length} products`;
  });
  await step("read-only: product keys and each product serves the agent", async () => {
    const creds = (await ok(agentCall(kp, "POST", "/v1/agent/credentials/renew"), "renew")).credentials;
    for (const c of creds) keys.set(c.product, c.key);
    must(PROBES.every((p) => keys.has(p.product)), `renew gave keys for ${[...keys.keys()].join(", ") || "no product"}`);
    const codes = await Promise.all(PROBES.map(async (p) => [p.name, await probe(p)] as const));
    must(codes.every(([, s]) => s >= 200 && s < 300), `not served: ${JSON.stringify(codes)}`);
    return codes.map(([n, s]) => `${n} ${s}`).join(", ");
  });
  await step("pause: every product refuses the agent within 60 s", async () => {
    await ok(call("POST", `/v1/agents/${encodeURIComponent(kp.did)}/pause`, { source: "app" }, auth), "pause");
    const times = await Promise.all(PROBES.map(async (p) => [p.name, await within(LIMIT, `${p.name} refusing`, async () => (await probe(p)) === 423)] as const));
    return times.map(([n, s]) => `${n} ${s.toFixed(0)} s`).join(", ");
  });
  await step("resume: the owner resumes in the app; every product serves the agent again", async () => {
    console.error(`\nResume ${kp.did} in the OpenEntity app now (Face ID). Waiting up to 10 minutes.`);
    await within(600, "the owner's resume", async () => (await call("GET", `/v1/agents/${encodeURIComponent(kp.did)}`, undefined, auth = await ownerAuth())).body?.state === "active");
    const times = await Promise.all(PROBES.map(async (p) => [p.name, await within(LIMIT, `${p.name} serving`, async () => { const s = await probe(p); return s >= 200 && s < 300; })] as const));
    return times.map(([n, s]) => `${n} ${s.toFixed(0)} s`).join(", ");
  });
}

// ---------------------------------------------------------------- run
try {
  await (PROD ? production() : staging());
} catch (e) {
  rows.push({ step: "setup", result: "FAIL", detail: (e as Error).message.slice(0, 300), seconds: "" });
}
const table = ["| Step | Result | Seconds | Detail |", "|---|---|---|---|", ...rows.map((r) => `| ${r.step} | ${r.result} | ${r.seconds} | ${r.detail.replace(/\|/g, "/")} |`)].join("\n");
console.log(`\n${PROD ? "Production" : "Staging"} app loop, ${new Date().toISOString().slice(0, 16)}Z\n\n${table}\n`);
process.exitCode = rows.some((r) => r.result === "FAIL") ? 1 : 0;
