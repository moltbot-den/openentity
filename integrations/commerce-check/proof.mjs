// Independent-agent proof for Agent Commerce Check (C3.4): a fresh merchant and a fresh agent, using only what the public docs
// show, against the live registry. A tiny Express merchant puts `expressCheck` in front of POST /buy; a throwaway did:key agent signs
// its requests with signRequest. Every decision's evidence_id is then fetched back from GET /v1/commerce/evidence/<id>.
//   node proof.mjs [--registry https://openentity.org] [--out report.json] [--mandate-case <module>]
// --mandate-case is a module whose default export is async ({ agent, merchantDid, buy }) => cases[]: the mandate cases (allow, step_up over the
// mandate's limit) need an owner's signed mandate/1, which only an owner device can issue, and the account's sign-in is closed in production
// until launch. ./proof-mandate.mjs runs them against a local registry whose owner is the published throwaway owner of test-vectors/keylog-1:
//   (cd registry && COMMERCE_VECTOR_OWNER=1 WRITE_PER_MINUTE=100000 IP_DAILY_LIMIT=1000000 node_modules/.bin/tsx scripts/local.ts 8799) &
//   node proof.mjs --registry http://127.0.0.1:8799 --mandate-case ./proof-mandate.mjs --out report-local.json
// Exit 0 when every case got the decision it expected and every evidence record exists and is intact; 1 otherwise.
import { writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import express from "express";
import { canonicalize, generateKeyPair, signRequest } from "@openentity/sdk";
import { expressCheck } from "./src/index.ts";

const { values: v } = parseArgs({ options: { registry: { type: "string", default: "https://openentity.org" }, out: { type: "string", default: "report.json" }, "mandate-case": { type: "string" } } });
const registry = v.registry.replace(/\/+$/, "");

// The merchant: the middleware from the guide, with a cart/1 built from the request alone. `?total=` is the price in minor units.
const policyOf = { open: { require_mandate: false }, strict: { require_mandate: true, require_owner: true } };
const app = express();
let merchantDid = "";
const cart = (req, agentDid) => {
  const total = Number(new URL(req.url).searchParams.get("total") ?? 1000);
  const mandate = (() => { try { return JSON.parse(Buffer.from(req.headers["oe-mandate"], "base64url").toString()).mandate_id; } catch { return null; } })();
  return { profile: "cart/1", merchant: merchantDid, agent_did: req.headers["x-claimed-agent"] ?? agentDid ?? "did:key:unknown", lines: [{ sku: "dataset-1", title: "Dataset", qty: 1, unit: total }], total, currency: "USD", rail: "credits", mandate_id: mandate };
};
const handler = (req, res) => res.json({ bought: true, decision: "allow", reasons: req.agentCheck.reasons, evidence_id: req.agentCheck.evidence_id });
// A buyer that got step_up retries with the owner's approval of that exact cart in `OE-Approval` (base64url JSON {approval, verifier_did, request_id}).
const approval = (req) => { try { return JSON.parse(Buffer.from(req.headers["oe-approval"], "base64url").toString()); } catch { return undefined; } };
const check = (policy) => expressCheck({ cart, policy, approval, endpoint: `${registry}/v1/commerce/check` });
app.post("/buy", check(policyOf.open), handler);
app.post("/buy-strict", check(policyOf.strict), handler);
const server = await new Promise((r) => { const s = app.listen(0, "127.0.0.1", () => r(s)); });
const origin = `http://127.0.0.1:${server.address().port}`;
merchantDid = `did:web:127.0.0.1%3A${server.address().port}`;

// The agent: a fresh did:key. `buy` sends one signed purchase to the merchant and records what came back.
const agent = await generateKeyPair();
const buy = async (path, { sign = true, signedFor, headers = {}, resend } = {}) => {  // returns {status, body, headers}
  const url = origin + path;
  const h = resend ?? (sign ? await signRequest({ method: "POST", url: signedFor ?? url, privateKey: agent, did: agent.did }) : {});
  const res = await fetch(url, { method: "POST", headers: { ...h, ...headers } });
  return { status: res.status, body: await res.json(), headers: h };
};

const cases = [];
const run = async (name, expect, reason, go) => {
  const r = await go();
  cases.push({ name, expect, reason, http_status: r.status, decision: r.body.decision ?? (r.status === 200 ? "allow" : undefined), reasons: r.body.reasons, evidence_id: r.body.evidence_id });
  return r;
};

await run("unsigned request", "deny", "request_unverified", () => buy("/buy", { sign: false }));
await run("signed for another host", "deny", "request_unverified", () => buy("/buy", { signedFor: "http://127.0.0.1:1/buy" }));
await run("cart names another agent", "deny", "agent_mismatch", () => buy("/buy", { headers: { "x-claimed-agent": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" } }));
const first = await run("signed, no mandate, mandate not required", "step_up", "no_mandate", () => buy("/buy"));
await run("same signed request sent again", "deny", "request_replayed", () => buy("/buy", { resend: first.headers }));
await run("signed, mandate required", "deny", "mandate_required", () => buy("/buy-strict"));
if (v["mandate-case"]) cases.push(...(await (await import(v["mandate-case"])).default({ agent, merchantDid, buy, origin })));

// Evidence: every id must exist and be intact (hash = sha256 of the RFC 8785 form without `hash`), and agree with what the merchant saw.
const sha256 = async (s) => Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))).toString("hex");
for (const c of cases) {
  const r = await fetch(`${registry}/v1/commerce/evidence/${c.evidence_id}`);
  const j = r.ok ? await r.json() : null;
  const rec = j?.record ?? j?.evidence ?? j;
  const { hash, intact, ...rest } = rec ?? {}; // `intact` is added to the answer; the hash covers the record without it
  c.evidence = rec && { http: r.status, server_intact: j.intact, local_intact: (await sha256(canonicalize(rest))) === hash, seq: rec.seq, hash, prev_hash: rec.prev_hash, decision: rec.decision, reasons: rec.reasons, agent_did: rec.agent_did };
    c.ok = !!(c.decision === c.expect && c.reasons?.includes(c.reason) && c.evidence?.http === 200 && c.evidence.server_intact === true && c.evidence.local_intact
    && c.evidence.decision === c.decision && JSON.stringify(c.evidence.reasons) === JSON.stringify(c.reasons) && (c.evidence.agent_did === null || c.evidence.agent_did === agent.did));
}
// The chain: where two of our records are neighbours, the later one's prev_hash is the earlier one's hash.
for (const c of cases) { const prev = cases.find((p) => p.evidence?.seq === c.evidence?.seq - 1); if (prev) c.chain_links_prev = prev.evidence.hash === c.evidence.prev_hash; }
const head = await (await fetch(`${registry}/v1/commerce/head`)).json();
const report = { registry, agent_did: agent.did, merchant_did: merchantDid, at: new Date().toISOString(), head, decisions: Object.fromEntries(["allow", "step_up", "deny"].map((d) => [d, cases.filter((c) => c.decision === d).length])), cases, passed: cases.length > 0 && cases.every((c) => c.ok && c.chain_links_prev !== false) };
writeFileSync(v.out, JSON.stringify(report, null, 2) + "\n");
server.close();
for (const c of cases) console.log(`${c.ok ? "PASS" : "FAIL"}  ${c.name}: ${c.decision} ${JSON.stringify(c.reasons)} ${c.evidence_id}`);
console.log(`${report.passed ? "PASSED" : "FAILED"}: ${JSON.stringify(report.decisions)} -> ${v.out}`);
process.exit(report.passed ? 0 : 1);
