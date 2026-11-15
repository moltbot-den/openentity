// Agent Commerce Check middleware: Express, Hono / Cloudflare Workers, Next.js route handlers. One call to the hosted check
// (POST https://openentity.org/v1/commerce/check) before you take an agent's purchase. No dependencies: each adapter is duck-typed.

export type Decision = "allow" | "step_up" | "deny";
/** The hosted answer. `evidence_id` is the hash-chained record to keep for disputes (400 days): GET /v1/commerce/evidence/<id>. */
export interface AgentCheck {
  decision: Decision;
  reasons: string[];
  agent_did?: string;
  owner_did?: string;
  mandate_id?: string;
  /** On step_up: the cart the owner must approve, and its digest (the approval/2.0 payload_digest). */
  cart?: unknown;
  cart_digest?: string;
  evidence_id: string;
}
export interface RequestInfo { method: string; url: string; headers: Record<string, string>; body?: string; /** The raw bytes, base64: what the hosted check verifies content-digest against. */ body_b64?: string }
export interface Options {
  /** Builds the cart/1 for this request. `agentDid` is the signer, parsed from the signature header (verified by the hosted check, not here). */
  cart: (req: RequestInfo, agentDid: string | undefined) => unknown | Promise<unknown>;
  /** agent_policy (min_level, require_owner, require_mandate, min_security_band, accept_issuers, min_owner_level) or {merchant: <did>} to use the one that merchant published. */
  policy?: Record<string, unknown>;
  /** The merchant's approval of this exact cart, when the buyer retries after a step_up: {approval, verifier_did, request_id}. */
  approval?: (req: RequestInfo) => unknown | Promise<unknown>;
  /** Default https://openentity.org/v1/commerce/check. */
  endpoint?: string;
  fetch?: typeof fetch;
  /** false = observe mode: attach `agentCheck`, never block. Default true: deny answers 403, step_up answers 428, both with the evidence id. */
  enforce?: boolean;
  /** The origin agents sign (scheme://host), when this server sits behind a proxy that changes it. */
  publicOrigin?: string;
  /** Called with every decision, to log them. */
  onDecision?: (c: AgentCheck, req: RequestInfo) => void;
}

export const ENDPOINT = "https://openentity.org/v1/commerce/check";
const lower = (h: Record<string, string | string[] | undefined>) => Object.fromEntries(Object.entries(h).flatMap(([k, v]) => (v === undefined ? [] : [[k.toLowerCase(), Array.isArray(v) ? v.join(", ") : v]])));

/** The agent DID named by the request's Signature-Input keyid (unverified; for building the cart only). */
export const agentDidOf = (headers: Record<string, string>): string | undefined => /keyid="([^"#]+)/.exec(headers["signature-input"] ?? "")?.[1];

/** The core: ask the hosted check about one request. */
export async function agentCheck(o: Options, req: RequestInfo): Promise<AgentCheck> {
  const headers = lower(req.headers);
  const cart = await o.cart({ ...req, headers }, agentDidOf(headers));
  const approval = await o.approval?.({ ...req, headers });
  const res = await (o.fetch ?? fetch)(o.endpoint ?? ENDPOINT, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ request: { method: req.method, url: req.url, headers, ...(req.body_b64 !== undefined ? { body_b64: req.body_b64 } : req.body !== undefined ? { body: req.body } : {}) }, cart, policy: o.policy ?? {}, ...(approval ? { approval } : {}) }),
  });
  const j = (await res.json().catch(() => null)) as AgentCheck | { error?: string; message?: string } | null;
  if (!res.ok || !j || !("decision" in j)) throw new Error(`commerce check failed: ${res.status} ${(j as { error?: string } | null)?.error ?? ""}`);
  return j;
}

const body = (c: AgentCheck) => ({ decision: c.decision, reasons: c.reasons, evidence_id: c.evidence_id, ...(c.cart ? { cart: c.cart, cart_digest: c.cart_digest } : {}) });
/** Fail closed: when the check itself cannot be reached an enforcing server refuses (503), an observing one carries on. */
const unavailable = { error: "commerce_check_unavailable", message: "the agent could not be checked; retry" };
const b64 = (b: ArrayBuffer | Uint8Array) => { const u = b instanceof Uint8Array ? b : new Uint8Array(b); let s = ""; for (let i = 0; i < u.length; i += 8192) s += String.fromCharCode(...u.subarray(i, i + 8192)); return btoa(s); }; // no Buffer: Workers
/** The body of a fetch Request as text (for the cart builder) and raw bytes (for the signature check). */
const bodyOf = async (r: Request) => (r.method === "GET" || r.method === "HEAD" ? {} : (async () => { const buf = await r.clone().arrayBuffer(); return { body: new TextDecoder().decode(buf), body_b64: b64(buf) }; })());
const originOf = (o: Options, url: string) => (o.publicOrigin ? o.publicOrigin.replace(/\/$/, "") + url.replace(/^https?:\/\/[^/]+/, "") : url);

// ---- Express (4 and 5). For a signed body, keep the raw bytes: express.json({ verify: (req, _res, buf) => (req.rawBody = buf) }).
export function expressCheck(o: Options) {
  return async (req: any, res: any, next: (e?: unknown) => void) => {
    const raw = req.rawBody ?? req.body;
    const info: RequestInfo = {
      method: req.method, url: originOf(o, `${req.protocol}://${req.get("host")}${req.originalUrl}`), headers: lower(req.headers),
      ...(typeof raw === "string" || Buffer.isBuffer(raw) ? { body: String(raw), body_b64: b64(typeof raw === "string" ? new TextEncoder().encode(raw) : raw) } : {}),
    };
    try {
      const c = (req.agentCheck = await agentCheck(o, info));
      o.onDecision?.(c, info);
      if (o.enforce === false || c.decision === "allow") return next();
      return res.status(c.decision === "deny" ? 403 : 428).json(body(c));
    } catch (e) {
      if (o.enforce === false) return next();
      return res.status(503).json(unavailable);
    }
  };
}

// ---- Hono and Cloudflare Workers: app.use("/buy", honoCheck(opts)); handlers read c.get("agentCheck").
export function honoCheck(o: Options) {
  return async (c: any, next: () => Promise<void>) => {
    const r: Request = c.req.raw;
    const info: RequestInfo = { method: r.method, url: originOf(o, r.url), headers: Object.fromEntries(r.headers), ...(await bodyOf(r)) };
    try {
      const k = await agentCheck(o, info);
      c.set("agentCheck", k);
      o.onDecision?.(k, info);
      if (o.enforce === false || k.decision === "allow") return next();
      return c.json(body(k), k.decision === "deny" ? 403 : 428);
    } catch {
      if (o.enforce === false) return next();
      return c.json(unavailable, 503);
    }
  };
}

// ---- Next.js route handlers (App Router) and any (Request) => Response handler: export const POST = nextCheck(opts, handler).
export function nextCheck<R extends Request>(o: Options, handler: (req: R & { agentCheck?: AgentCheck }, ctx?: unknown) => Response | Promise<Response>) {
  return async (req: R, ctx?: unknown): Promise<Response> => {
    const info: RequestInfo = { method: req.method, url: originOf(o, req.url), headers: Object.fromEntries(req.headers), ...(await bodyOf(req)) };
    const withCheck = req as R & { agentCheck?: AgentCheck };
    try {
      const c = (withCheck.agentCheck = await agentCheck(o, info));
      o.onDecision?.(c, info);
      if (o.enforce !== false && c.decision !== "allow") return Response.json(body(c), { status: c.decision === "deny" ? 403 : 428 });
    } catch {
      if (o.enforce !== false) return Response.json(unavailable, { status: 503 });
    }
    return handler(withCheck, ctx);
  };
}
