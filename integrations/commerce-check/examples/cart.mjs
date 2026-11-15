// Shared by the three JavaScript examples: the cart/1 for "POST /buy?total=<minor units>", from the request alone.
export const MERCHANT = "did:web:shop.example";
export const POLICY = { require_mandate: true, require_owner: true }; // or { merchant: "did:web:shop.example" } to use the policy you published

/** The mandate id inside the agent's OE-Mandate header, so the cart can name the mandate it spends under. */
const mandateId = (headers) => {
  try { return JSON.parse(Buffer.from(headers["oe-mandate"], "base64url").toString()).mandate_id; } catch { return null; }
};

export const cart = (req, agentDid) => {
  const total = Number(new URL(req.url).searchParams.get("total") ?? 1000);
  return {
    profile: "cart/1", merchant: MERCHANT, agent_did: agentDid ?? "did:key:unknown",
    lines: [{ sku: "dataset-1", title: "Dataset", qty: 1, unit: total }], total, currency: "USD", rail: "credits", mandate_id: mandateId(req.headers),
  };
};
