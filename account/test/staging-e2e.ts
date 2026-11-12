// Live proof against staging, not part of the suite: an owner (email code injected through the Data API, so no mail is
// sent; a software passkey and device key), a key log, pairing, the agent channel over HTTP and the WebSocket, pause
// and resume. Everything it creates is deleted at the end.
//   AWS_PROFILE=openentity npx tsx account/test/staging-e2e.ts
import { execFileSync } from "node:child_process";
import { createHash, createHmac, generateKeyPairSync, randomBytes, randomUUID, sign as nodeSign } from "node:crypto";
import { GetParametersCommand, SSMClient } from "@aws-sdk/client-ssm";
import { buildPresentation, canonicalize, generateKeyPair, pairSas, signRequest } from "@openentity/sdk";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import { dataApiDb } from "../src/db.ts";
import { lowS } from "../src/keylog.ts";

const HOST = "staging.account.openentity.org", BASE = `https://${HOST}`, WSS = `wss://agents.${HOST}/`, SERVICE = `did:web:${HOST}`;
const outputs = JSON.parse(execFileSync("aws", ["cloudformation", "describe-stacks", "--stack-name", "OpenEntityAccountStaging", "--region", "us-east-1", "--output", "json"], { encoding: "utf8" })).Stacks[0].Outputs;
const out = (k: string) => outputs.find((o: any) => o.OutputKey === k).OutputValue;
const db = dataApiDb({ resourceArn: out("DbClusterArn"), secretArn: out("DbSecretArn"), database: "account" });
const ssm = await new SSMClient({ region: "us-east-1" }).send(new GetParametersCommand({ Names: ["/openentity/account/code_pepper", "/openentity/account/code_pepper_staging"], WithDecryption: true }));
const pepper = (ssm.Parameters!.find((p) => p.Name!.endsWith("_staging")) ?? ssm.Parameters![0]).Value!;

const step = (what: string) => console.log(`ok  ${what}`);
async function call(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
  const r = await fetch(`${BASE}${path}`, { method, headers: { "content-type": "application/json", ...headers }, body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body) });
  const text = await r.text();
  let json: any = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  if (!r.ok && !(headers["x-expect"] && String(r.status) === headers["x-expect"])) throw new Error(`${method} ${path} -> ${r.status} ${text.slice(0, 300)}`);
  return { status: r.status, body: json };
}
const p256 = () => {
  const k = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const { x, y } = k.publicKey.export({ format: "jwk" }) as any;
  const kid = createHash("sha256").update(`{"crv":"P-256","kty":"EC","x":"${x}","y":"${y}"}`).digest("base64url");
  const sign = (data: string | Uint8Array) => Buffer.from(lowS(new Uint8Array(nodeSign("sha256", Buffer.from(data), { key: k.privateKey, dsaEncoding: "ieee-p1363" })))).toString("base64url");
  return { k, x, y, kid, jwk: { kty: "EC", crv: "P-256", x, y }, sign };
};

const email = `e2e-${randomUUID()}@staging-e2e.openentity.org`, install = randomUUID();
const client = { platform: "ios", install_id: install, app_version: "e2e", device_model: "script" };
let accountId = "", ownerId = "", agentDid = "";
try {
  // Owner: an email code row with a known code (what POST /v1/auth/email/start stores), then the real verify.
  const challenge = `eml_e2e${randomBytes(8).toString("hex")}`, code = String(Math.floor(Math.random() * 1e8)).padStart(8, "0"), t = Math.floor(Date.now() / 1000);
  await db.run("INSERT INTO email_codes (id, email, code_mac, install_id, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6)",
    [challenge, email, createHmac("sha256", pepper).update(`${challenge}:${code}`).digest("hex"), install, t, t + 600]);
  const s = (await call("POST", "/v1/auth/email/verify", { challenge_id: challenge, code, client })).body;
  accountId = s.account.id;
  const auth = { authorization: `Bearer ${s.access_token}` };
  step(`signed in ${accountId}`);

  // Root passkey: a software authenticator answers the registration ceremony (attestation none, UV).
  const opts = (await call("POST", "/v1/auth/passkey/options", { mode: "register", client }, auth)).body;
  const root = p256(), credId = randomBytes(16);
  const cose = isoCBOR.encode(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(root.x, "base64url")], [-3, Buffer.from(root.y, "base64url")]]));
  const authData = Buffer.concat([createHash("sha256").update(HOST).digest(), Buffer.from([0x45, 0, 0, 0, 0]), Buffer.alloc(16), Buffer.from([0, 16]), credId, Buffer.from(cose)]);
  const clientData = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge: opts.options.challenge, origin: BASE, crossOrigin: false }));
  const attObj = isoCBOR.encode(new Map<string, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", new Uint8Array(authData)]]) as any);
  const reg = (await call("POST", "/v1/auth/passkey/verify", { challenge_id: opts.challenge_id, client, response: {
    id: credId.toString("base64url"), rawId: credId.toString("base64url"), type: "public-key", clientExtensionResults: {},
    response: { clientDataJSON: clientData.toString("base64url"), attestationObject: Buffer.from(attObj).toString("base64url"), transports: ["internal"] },
  } }, auth)).body;
  step(`root passkey registered (kid ${reg.credential.kid})`);

  // Genesis, signed by a device approver (no receipt: attestation none).
  const approver = p256();
  const unsigned = { v: 1, seq: 1, prev: null, op: "genesis", ts: Math.floor(Date.now() / 1000), body: { root: reg.credential, approver: { kid: approver.kid, type: "p256", jwk: approver.jwk, label: "e2e", platform: "ios", key_storage: "secure_enclave", attestation: { type: "none", verified: false } } } };
  const line = canonicalize({ ...unsigned, auth: { kid: approver.kid, form: "p256", signature: approver.sign(canonicalize(unsigned)) } });
  const A = "abcdefghijklmnopqrstuvwxyz234567", h = createHash("sha256").update(line).digest();
  let bits = 0, value = 0;
  for (const x of h) { value = (value << 8) | x; bits += 8; while (bits >= 5) ownerId += A[(value >> (bits -= 5)) & 31]; value &= (1 << bits) - 1; }
  if (bits) ownerId += A[(value << (5 - bits)) & 31];
  await call("POST", `/o/${ownerId}/log`, { line }, auth);
  const ownerDid = `did:web:${HOST}:o:${ownerId}`;
  const log = await fetch(`${BASE}/o/${ownerId}/log`);
  if ((await log.text()) !== `${line}\n` || !log.headers.get("x-oe-first-seen-at")) throw new Error("the log does not read back byte for byte");
  step(`key log ${ownerDid}`);
  const sign = (req: any, decision = "approve") => Buffer.from(JSON.stringify({
    version: "approval/2.0", verifier_did: req.verifier_did, owner_did: req.owner_did, request_id: req.request_id, payload_digest: req.payload_digest, decision, expires_at: req.expires_at,
    device_id: approver.kid, form: "p256", signature: approver.sign(["approval/2.0", req.verifier_did, req.owner_did, req.request_id, req.payload_digest, decision, String(req.expires_at)].join("|")),
  })).toString("base64url");

  // Pairing: code, the agent's claim, the owner's confirm.
  const started = Date.now();
  const pairing = (await call("POST", "/v1/pairings", undefined, auth)).body;
  const kp = await generateKeyPair();
  agentDid = kp.did;
  const asAgent = async (method: string, path: string, body?: unknown, expect?: string) => {
    const raw = body === undefined ? undefined : JSON.stringify(body);
    const sig = await signRequest({ method, url: `${BASE}${path}`, body: raw ? new TextEncoder().encode(raw) : undefined, privateKey: kp, did: kp.did });
    return call(method, path, raw, { ...sig, ...(expect ? { "x-expect": expect } : {}) });
  };
  const claim = (await asAgent("POST", "/v1/pair", { code: pairing.code, presentation: await buildPresentation(kp, { audience: SERVICE, nonce: `pair:${pairing.code}` }), framework: "e2e", sdk: "openentity", sdk_version: "e2e" })).body;
  if (claim.sas.names.join() !== pairSas(pairing.code, kp.did).join()) throw new Error("match strings differ");
  const detail = (await call("GET", `/v1/pairings/${pairing.id}`, undefined, auth)).body;
  await call("POST", `/v1/pairings/${pairing.id}/confirm`, { permissions: ["owner.message", "owner.status", "owner.approval"] }, { ...auth, "x-oe-approval": sign(detail.approval_request) });
  await new Promise((r) => setTimeout(r, 2100));
  const status = (await asAgent("GET", `/v1/pair/${pairing.id}`)).body;
  if (status.state !== "confirmed" || status.owner_did !== ownerDid) throw new Error(`pair status ${JSON.stringify(status)}`);
  step(`paired ${kp.did} in ${((Date.now() - started) / 1000).toFixed(1)} s (match: ${claim.sas.names.join(", ")}; keys: ${status.credentials?.length ?? 0})`);

  // The WebSocket: a signed upgrade, then frames as they come.
  const frames: any[] = [];
  const sock = new WebSocket(WSS, { headers: await signRequest({ method: "GET", url: WSS, privateKey: kp, did: kp.did }) } as any);
  const closed = new Promise<void>((r) => sock.addEventListener("close", () => r()));
  sock.addEventListener("message", (e) => frames.push(JSON.parse(String(e.data))));
  await new Promise<void>((ok, no) => { sock.addEventListener("open", () => ok()); sock.addEventListener("error", () => no(new Error("WebSocket upgrade refused"))); });
  sock.send(JSON.stringify({ action: "heartbeat" }));
  const until = async (test: () => boolean, what: string) => {
    for (let i = 0; i < 50 && !test(); i++) await new Promise((r) => setTimeout(r, 200));
    if (!test()) throw new Error(`no ${what} on the socket: ${JSON.stringify(frames)}`);
  };
  await until(() => frames.some((f) => f.type === "heartbeat"), "heartbeat answer (MOCK route)");
  step("WebSocket open; heartbeat answered without the function");

  const msg = (await call("POST", `/v1/agents/${encodeURIComponent(kp.did)}/messages`, { text: "hello from the owner" }, auth)).body;
  await until(() => frames.some((f) => f.id === msg.id), "owner message");
  sock.send(JSON.stringify({ action: "ack", ids: [msg.id] }));
  await asAgent("POST", "/v1/agent/messages", { text: "hello from the agent" });
  await asAgent("POST", "/v1/agent/status", { state: "running", summary: "e2e", progress: 0.5 });
  const thread = (await call("GET", `/v1/agents/${encodeURIComponent(kp.did)}/messages`, undefined, auth)).body.messages;
  const agentView = (await call("GET", `/v1/agents/${encodeURIComponent(kp.did)}`, undefined, auth)).body;
  if (thread.length !== 2 || agentView.status?.summary !== "e2e") throw new Error("messages or status missing");
  step("messages both ways, status on the owner's view");

  // An attachment through real S3: the presigned PUT carries the signed type and length, a message names the upload,
  // and the owner's download is a 302 to a presigned GET.
  const file = "e2e attachment";
  const up = (await asAgent("POST", "/v1/agent/uploads", { name: "e2e.txt", content_type: "text/plain", size: Buffer.byteLength(file) })).body;
  const put = await fetch(up.url, { method: up.method, headers: up.headers, body: file });
  if (!put.ok) throw new Error(`S3 PUT -> ${put.status} ${(await put.text()).slice(0, 300)}`);
  await asAgent("POST", "/v1/agent/messages", { text: "see attached", attachments: [up.upload_id] });
  const dl = await fetch(`${BASE}/v1/attachments/${up.upload_id}`, { headers: auth, redirect: "manual" });
  const fileUrl = dl.headers.get("location") ?? "";
  if (dl.status !== 302 || (await (await fetch(fileUrl)).text()) !== file) throw new Error(`attachment download -> ${dl.status}`);
  step("attachment: presigned PUT to S3, carried by a message, downloaded by the owner through a 302");

  // Pause: no approval; the socket hears the pause command and close_code 4001, then closes.
  await call("POST", `/v1/agents/${encodeURIComponent(kp.did)}/pause`, { source: "app" }, auth);
  await until(() => frames.some((f) => f.close_code === 4001), "4001 frame");
  await Promise.race([closed, new Promise((_, no) => setTimeout(() => no(new Error("socket not closed")), 10_000))]);
  if ((await asAgent("POST", "/v1/agent/messages", { text: "still here" }, "423")).status !== 423) throw new Error("a paused agent could still message");
  step("paused: pause command, close_code 4001, socket closed, 423 on the next call");

  const req = (await call("POST", "/v1/step-up", { action: "agent.resume", params: { agent_did: kp.did } }, auth)).body;
  if ((await call("POST", `/v1/agents/${encodeURIComponent(kp.did)}/resume`, undefined, { ...auth, "x-oe-approval": sign(req) })).body.state !== "active") throw new Error("resume failed");
  step("resumed with an approval/2.0 step-up");
  await call("DELETE", `/v1/agents/${encodeURIComponent(kp.did)}`, undefined, auth);
  if (await db.first("SELECT 1 FROM messages WHERE agent_did = $1 UNION ALL SELECT 1 FROM uploads WHERE agent_did = $1", [kp.did])) throw new Error("unlink left the thread or uploads");
  if ((await fetch(fileUrl)).ok) throw new Error("unlink left the attachment in S3");
  step("unlinked: thread, uploads and the S3 object gone");
} catch (e) {
  console.error(`FAILED: ${(e as Error).message}`);
  process.exitCode = 1;
} finally {
  // Leave nothing behind: every row this run created. One failed delete never stops the others.
  const del = (sql: string, p: unknown[]) => db.run(sql, p).catch((e) => console.error(`cleanup: ${sql.split(" WHERE")[0]}: ${(e as Error).message}`));
  if (agentDid) for (const t of ["inbox", "messages", "uploads", "agent_approvals", "pause_changes", "agent_products"]) await del(`DELETE FROM ${t} WHERE agent_did = $1`, [agentDid]);
  if (agentDid) await del("DELETE FROM agents WHERE did = $1", [agentDid]);
  if (accountId) {
    for (const t of ["pairings", "step_ups", "enrollments", "push_tokens"]) await del(`DELETE FROM ${t} WHERE account_id = $1`, [accountId]);
    if (ownerId) await del("DELETE FROM keylog_entries WHERE owner_id = $1", [ownerId]);
    await del("DELETE FROM refresh_tokens WHERE session_id IN (SELECT id FROM sessions WHERE account_id = $1)", [accountId]);
    for (const t of ["sessions", "methods", "passkey_challenges"]) await del(`DELETE FROM ${t} WHERE account_id = $1`, [accountId]);
    await del("DELETE FROM accounts WHERE id = $1", [accountId]);
  }
  await del("DELETE FROM email_codes WHERE email = $1", [email]);
  console.log("cleaned up");
}
