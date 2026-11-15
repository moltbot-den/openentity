// The mandate cases of proof.mjs, for a local registry started with COMMERCE_VECTOR_OWNER=1 (registry/scripts/local.ts): the owner is the
// published throwaway owner of test-vectors/keylog-1, whose iPhone approver key signs the mandate and the approval. Against openentity.org
// these cases need a real owner's device (the account's sign-in is closed in production until launch), so they run here.
import { readFileSync } from "node:fs";
import { p256 } from "@noble/curves/nist.js";
import { approvalDigest, mandateDigest } from "@openentity/sdk";

const vec = (p) => JSON.parse(readFileSync(new URL(`../../test-vectors/${p}`, import.meta.url), "utf8"));
const OWNER = vec("keylog-1/add-approver.json").did, IOS = vec("approval-2.0/keys.json").keys.ios;
const unhex = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
const sign = (digest) => ({ device_id: IOS.kid, form: "p256", signature: Buffer.from(p256.sign(digest, unhex(IOS.secret), { prehash: false, lowS: true })).toString("base64url") });
const B32 = "abcdefghijklmnopqrstuvwxyz234567";

export default async function ({ agent, merchantDid, buy }) {
  const t = Math.floor(Date.now() / 1000), id = "md_" + Array.from(crypto.getRandomValues(new Uint8Array(26)), (x) => B32[x % 32]).join("");
  const body = {
    version: "mandate/1", mandate_id: id, issuer_did: OWNER, agent_did: agent.did, issued_at: t - 60, expires_at: t + 86400,
    limits: { currency: "USD", per_tx_max: 5000, period: "P1D", period_max: 20000, total_max: 100000 }, scope: { merchants: [merchantDid], rails: ["credits"] },
    step_up_over: 2500, status: `https://account.openentity.org/v1/mandates/${id}/status`,
  };
  const header = { "oe-mandate": Buffer.from(JSON.stringify({ ...body, signature: sign(mandateDigest(body)) })).toString("base64url") };
  const row = (name, expect, reason, r) => ({ name, expect, reason, http_status: r.status, decision: r.body.decision, reasons: r.body.reasons, evidence_id: r.body.evidence_id });

  const cases = [row("mandate covers the cart", "allow", "mandate_covers_cart", await buy("/buy-strict?total=1000", { headers: header }))];
  const su = await buy("/buy-strict?total=4000", { headers: header });
  cases.push(row("cart over the mandate's step_up_over", "step_up", "step_up_over", su));

  // The owner approves that exact cart (approval/2.0 over its digest); the agent retries with a fresh signature and the approval.
  const a = { version: "approval/2.0", verifier_did: merchantDid, owner_did: OWNER, request_id: "req_proof_1", payload_digest: su.body.cart_digest, decision: "approve", expires_at: t + 300 };
  const approval = { approval: { ...a, ...sign(approvalDigest(a)) }, verifier_did: merchantDid, request_id: a.request_id };
  const oe = { ...header, "oe-approval": Buffer.from(JSON.stringify(approval)).toString("base64url") };
  cases.push(row("owner approved that exact cart", "allow", "owner_approved_cart", await buy("/buy-strict?total=4000", { headers: oe })));
  cases.push(row("the same approval used twice", "deny", "approval_replayed", await buy("/buy-strict?total=4000", { headers: oe })));
  cases.push(row("cart over per_tx_max", "step_up", "mandate_over_limit", await buy("/buy-strict?total=9000", { headers: header })));
  return cases;
}
