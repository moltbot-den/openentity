# @openentity/commerce-check

One line of middleware before you accept an agent's purchase: it calls the hosted Agent Commerce Check (`POST https://openentity.org/v1/commerce/check`) and answers `allow`, `step_up` (HTTP 428, the owner must approve this cart) or `deny` (HTTP 403), each with an `evidence_id` you keep for disputes. Free, no key. Express, Hono and Cloudflare Workers, Next.js route handlers; no dependencies.

Guide, the checks, every reason code and the evidence record: https://openentity.org/guides/commerce-check

<!-- oe:skip needs @openentity/commerce-check, released with the next package batch -->
```ts
import { expressCheck } from "@openentity/commerce-check";

app.post("/buy", expressCheck({ cart: cartFor, policy: { require_mandate: true, require_owner: true } }),
  (req, res) => res.json({ bought: true, evidence_id: req.agentCheck.evidence_id }));
```

`cartFor(req, agentDid)` returns your `cart/1`. `merchant` is the `did:web` of the host agents call (`did:web:shop.example`), and the agent must sign that exact URL. Behind a proxy set `publicOrigin`. `enforce: false` is observe mode. See `examples/` for Express, Hono and Next.js.

`proof.mjs` is the independent run: a fresh merchant and a fresh agent against the hosted check, one case per decision, then every `evidence_id` fetched back and its hash checked.

<!-- oe:skip runs against the live openentity.org from a checkout of the repository -->
```sh
node proof.mjs --out report.json    # live: deny and step_up (an agent alone has no owner mandate)
```

`allow` needs an owner's mandate; `proof-mandate.mjs` shows it against a local registry that trusts the published throwaway owner (`COMMERCE_VECTOR_OWNER=1`, see the header of `proof.mjs`).

MIT.
