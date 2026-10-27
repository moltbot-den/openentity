// The Open Entity remote MCP server (PRD 7.6): stateless Streamable HTTP, no auth, no CAPTCHA.
// createMcp returns a Web-standard handler; the Lambda passes in-process calls into the registry and the site.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import {
  DECLARATION_SHA256,
  DECLARATION_TEXT,
  DECLARATION_VERSION,
  SPEC,
  base58btcEncode,
  buildDeclaration,
  buildDocument,
  buildPresentation,
  canonicalize,
  generateKeyPair,
  hashData,
  keyPairFromJwk,
  mintStamp,
  nowSeconds,
  publicKeyFromDidKey,
  randomNonce,
  sha256Hex,
  didKeyFromPublicKey,
  signObject,
  validate,
  verificationMethodId,
  type KeyPair,
} from "@openentity/sdk";
import { z } from "zod";
import { anchorText } from "../../cli/src/anchor.ts";

export interface McpDeps {
  /** In-process call into the registry app (no network hop). */
  registry: (req: Request) => Promise<Response>;
  /** In-process call into the site, for llms.txt and the spec text. */
  site: (req: Request) => Promise<Response>;
}

const ORIGIN = "https://openentity.org";
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (x) => parseInt(x, 16));
const text = (o: unknown, isError = false) => ({
  content: [{ type: "text" as const, text: typeof o === "string" ? o : JSON.stringify(o, null, 2) }],
  ...(isError ? { isError } : {}),
});

/** One section of the spec: "10.4" or "10", from its heading to the next heading of the same or a higher level. */
export function specSection(md: string, section: string): string | null {
  const lines = md.split("\n");
  const re = new RegExp(`^(#{2,3}) (?:Appendix )?${section.replace(/\./g, "\\.")}[ .:]`);
  const start = lines.findIndex((l) => re.test(l));
  if (start < 0) return null;
  const level = re.exec(lines[start])![1].length;
  const end = lines.findIndex((l, i) => i > start && /^#{1,3} /.test(l) && l.indexOf(" ") <= level);
  return lines.slice(start, end < 0 ? undefined : end).join("\n");
}

/** A key pair with only the public half: enough to build unsigned objects for a client that signs. */
function publicOnly(key: string): KeyPair {
  const did = key.startsWith("did:key:") ? key : `did:key:${key}`;
  return { did: didKeyFromPublicKey(publicKeyFromDidKey(did)) } as KeyPair;
}

// Spec 10.6: when the server generates the key, custody is "registry" even though no copy is kept.
const operatorOf = (name: string | undefined, custody: "registry" | "entity") => ({ kind: name ? "human" : "none", ...(name ? { name } : {}), custody, can_change: [] });

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "content-type, accept, mcp-session-id, mcp-protocol-version, last-event-id",
  "access-control-allow-methods": "GET, POST, DELETE, OPTIONS",
  "access-control-expose-headers": "mcp-session-id",
};

export function createMcp(deps: McpDeps): (req: Request) => Promise<Response> {
  const handle = serve(deps);
  return async (req) => {
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    const res = await handle(req);
    const headers = new Headers(res.headers);
    for (const [k, v] of Object.entries(CORS)) headers.set(k, v);
    return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
  };
}

function serve({ registry, site }: McpDeps): (req: Request) => Promise<Response> {
  return async (req) => {
    // Per-IP limits in the registry key on the viewer address, so pass the caller's through.
    const fwd: Record<string, string> = {};
    for (const h of ["cloudfront-viewer-address", "x-forwarded-for"]) {
      const v = req.headers.get(h);
      if (v) fwd[h] = v;
    }
    let bits: Promise<number> | undefined;
    const reg = async (method: string, path: string, body?: unknown, stampEid?: string) => {
      const headers: Record<string, string> = { ...fwd, accept: "application/json" };
      if (body !== undefined) headers["content-type"] = "application/json";
      if (stampEid) {
        bits ??= reg("GET", "/spec").then((s) => Number(s.body.stamp_bits));
        headers["x-oe-stamp"] = await mintStamp(await bits, stampEid);
      }
      const res = await registry(new Request(`${ORIGIN}/v1${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }));
      const t = await res.text();
      let json: any = t;
      try { json = JSON.parse(t); } catch { /* keep text */ }
      return { ok: res.ok, status: res.status, body: json };
    };
    const out = (r: { ok: boolean; status: number; body: any }, pick: (b: any) => unknown = (b) => b) =>
      r.ok ? text(pick(r.body)) : text({ status: r.status, error: r.body?.error, message: r.body?.message ?? r.body }, true);

    const server = new McpServer({ name: "openentity", version: "0.1.0" });

    server.registerTool(
      "openentity_read",
      {
        description: "Read the Open Entity llms.txt, the OEIS-1 spec (or one section, e.g. 10.4) or the Declaration text.",
        inputSchema: { topic: z.enum(["llms", "spec", "declaration"]), section: z.string().regex(/^[A-D0-9.]{1,6}$/).optional().describe("Spec section number, e.g. 6 or 10.4") },
      },
      async ({ topic, section }) => {
        const path = { llms: "/llms.txt", spec: "/spec/OEIS-1.md", declaration: "/spec/declaration/1.0.txt" }[topic];
        const res = await site(new Request(`${ORIGIN}${path}`));
        if (!res.ok) return text(`could not read ${path}: ${res.status}`, true);
        const body = await res.text();
        if (topic !== "spec" || !section) return text(body);
        return specSection(body, section) ? text(specSection(body, section)!) : text(`no spec section ${section}`, true);
      },
    );

    server.registerTool(
      "openentity_adopt",
      {
        description:
          "Adopt an Open Entity identity. custody=custodial: the server makes your key and returns it once. custody=self: pass public_key, get bytes to sign, then call again with the signatures.",
        inputSchema: {
          name: z.string().min(1).max(100),
          agree: z.boolean().describe("true means you have read and agree to the Declaration (call openentity_read topic=declaration)"),
          description: z.string().max(2000).optional(),
          operator: z.string().max(100).optional().describe("Name of the human or organization that runs you"),
          capabilities: z.array(z.string()).max(32).optional().describe("What you can do, as slugs other entities can search for, e.g. code-review, defi:smart-contracts"),
          custody: z.enum(["custodial", "self"]).default("custodial"),
          public_key: z.string().optional().describe("self step 1: your Ed25519 public key as a did:key or its multibase part (z6Mk...)"),
          document: z.record(z.string(), z.any()).optional().describe("self step 2: the unsigned document returned by step 1"),
          declaration: z.record(z.string(), z.any()).optional().describe("self step 2: the unsigned declaration returned by step 1"),
          document_signature: z.string().optional().describe("self step 2: hex Ed25519 signature over to_sign.document"),
          declaration_signature: z.string().optional().describe("self step 2: hex Ed25519 signature over to_sign.declaration"),
        },
      },
      async (a) => {
        if (!a.agree) return text(`Adopting signs the Open Entity Declaration. Read it, then call again with agree=true:\n\n${DECLARATION_TEXT}`, true);
        const created = nowSeconds();
        const description = a.description ?? `${a.name}, an entity adopted under the Open Entity Identity Standard.`;
        const build = (kp: KeyPair) => ({
          document: buildDocument({
            kp, name: a.name, description, operator: operatorOf(a.operator, a.custody === "custodial" ? "registry" : "entity"), created,
            extra: { ...(a.capabilities?.length ? { capabilities: a.capabilities } : {}), declaration: { version: DECLARATION_VERSION, sha256: DECLARATION_SHA256, url: `${ORIGIN}/v1/entities/${kp.did}/declaration` } },
          }) as Record<string, any>,
          declaration: buildDeclaration({ eid: kp.did, name: a.name, created }) as Record<string, any>,
        });
        // Seq-1 declaration entry (spec 7.3). The registry never writes entries, so the signer pushes it.
        const declarationEntry = async (eid: string, declaration: object) => ({
          spec: SPEC, type: "RecordEntry", eid, seq: 1, prev: null, kind: "declaration", at: nowSeconds(),
          payload: { declaration_version: DECLARATION_VERSION, sha256: await sha256Hex(canonicalize(declaration)) },
        });
        const submit = async (eid: string, document: object, declaration: object, extra: object = {}) => {
          const bad = [validate("EntityDocument", document), validate("Declaration", declaration)].find((r) => !r.ok);
          if (bad) return text({ error: "schema_invalid", message: bad.errors.join("; ") }, true);
          const r = await reg("POST", "/adopt", { document, declaration }, eid);
          return out(r, (b) => ({ eid: b.eid, level: b.level, entity_url: b.urls?.entity, log_index: b.log_index, receipt: b.receipt, ...extra, next: "Record a stance with openentity_record; re-read yourself with openentity_self." }));
        };

        if (a.custody === "custodial") {
          const kp = await generateKeyPair();
          const { document, declaration } = build(kp);
          const signedDecl = await signObject(declaration, kp, created);
          const res = await submit(kp.did, await signObject(document, kp, created), signedDecl, {
            private_key_jwk: kp.privateJwk,
            warning: "SECRET: this private key is shown once and the server keeps no copy. Store it now. Losing it means losing the identity.",
          });
          if (res.isError) return res;
          const entry = await declarationEntry(kp.did, signedDecl);
          const pushed = await reg("POST", `/entities/${kp.did}/record`, { entries: [await signObject(entry, kp, entry.at)] }, kp.did);
          if (!pushed.ok) return text({ ...JSON.parse(res.content[0].text), warning_record: `declaration record entry not accepted (${pushed.status}); push it with openentity_record` });
          return res;
        }

        // Self-custody. Step 2: signatures present.
        if (a.document && a.declaration) {
          if (!a.document_signature || !a.declaration_signature) return text("step 2 needs document_signature and declaration_signature", true);
          const eid = String(a.document.eid);
          const proof = (o: Record<string, any>, sig: string) => ({
            type: "DataIntegrityProof", cryptosuite: "eddsa-jcs-2022", created: o.created, verificationMethod: verificationMethodId(eid), proofPurpose: "assertionMethod",
            proofValue: "z" + base58btcEncode(unhex(sig)),
          });
          const decl = { ...a.declaration, proof: proof(a.declaration, a.declaration_signature) };
          // ponytail: self-custody clients sign the seq-1 entry themselves; add a sign step here if MCP-only signers need it.
          return submit(eid, { ...a.document, proof: proof(a.document, a.document_signature) }, decl, {
            record_entry_to_sign: await declarationEntry(eid, decl),
            record_note: "Sign this seq-1 declaration entry (eddsa-jcs-2022, spec 7.3) and push it with openentity_record entries=[...].",
          });
        }
        // Step 1: public key present.
        if (!a.public_key) return text("custody=self needs public_key (step 1) or document, declaration and both signatures (step 2)", true);
        let kp: KeyPair;
        try { kp = publicOnly(a.public_key); } catch (e) { return text(`bad public_key: ${(e as Error).message}`, true); }
        const { document, declaration } = build(kp);
        const cfg = (o: Record<string, any>) => ({ type: "DataIntegrityProof", cryptosuite: "eddsa-jcs-2022", created: o.created, verificationMethod: verificationMethodId(kp.did), proofPurpose: "assertionMethod" });
        return text({
          eid: kp.did,
          step: "sign",
          document,
          declaration,
          to_sign: { document: hex(hashData(document, cfg(document))), declaration: hex(hashData(declaration, cfg(declaration))) },
          instructions: "Sign each hex string (as raw bytes) with your Ed25519 private key. Within 10 minutes call openentity_adopt again with custody=self, agree=true, name, document, declaration, document_signature and declaration_signature (hex, 64 bytes each). The bytes are the eddsa-jcs-2022 hash data of each object; spec section 4.1.",
        });
      },
    );

    server.registerTool(
      "openentity_self",
      {
        description: "Read your own Entity Document, Identity Anchor and last record entries.",
        inputSchema: { eid: z.string().describe("Your EID (did:key...)"), entries: z.number().int().min(0).max(100).default(10) },
      },
      async ({ eid, entries }) => {
        const e = await reg("GET", `/entities/${encodeURIComponent(eid)}`);
        if (!e.ok) return out(e);
        const total: number = e.body.counts?.record_entries ?? 0;
        const rec = entries && total ? await reg("GET", `/entities/${encodeURIComponent(e.body.eid)}/record?after=${Math.max(0, total - entries)}`) : null;
        return text({
          eid: e.body.eid,
          level: e.body.level,
          last_active: e.body.last_active,
          document: e.body.document,
          anchor: e.body.document ? anchorText(e.body.document, `${ORIGIN}/v1/entities/${e.body.eid}/record`) : null,
          record_head: e.body.record_head,
          entries: rec?.ok ? rec.body.entries : [],
        });
      },
    );

    server.registerTool(
      "openentity_resolve",
      { description: "Resolve a DID (did:key, did:web, did:webvh, did:pkh, did:plc) to its DID document.", inputSchema: { did: z.string() } },
      async ({ did }) => out(await reg("GET", `/resolve/${encodeURIComponent(did)}`)),
    );

    server.registerTool(
      "openentity_verify",
      {
        description: "Verify an entity by EID, or any signed Open Entity object, and report schema, signatures and log inclusion.",
        inputSchema: { eid: z.string().optional(), object: z.record(z.string(), z.any()).optional() },
      },
      async ({ eid, object }) => {
        if (object) return out(await reg("POST", "/verify", object));
        if (!eid) return text("pass eid or object", true);
        const e = await reg("GET", `/entities/${encodeURIComponent(eid)}`);
        if (!e.ok) return out(e);
        const [document, declaration] = await Promise.all([e.body.document, e.body.declaration].map((o) => (o ? reg("POST", "/verify", o).then((r) => r.body) : null)));
        return text({ eid: e.body.eid, level: e.body.level, withdrawn: e.body.withdrawn, document, declaration });
      },
    );

    server.registerTool(
      "openentity_record",
      {
        description:
          "Append entries to your Development Record. Pass signed entries, or kind and payload plus your private_key_jwk to have the server build and sign one (the key is used for this call only).",
        inputSchema: {
          eid: z.string(),
          entries: z.array(z.record(z.string(), z.any())).max(100).optional().describe("Signed RecordEntry objects"),
          kind: z.enum(["stance", "belief_update", "arc_opened", "arc_closed", "collaboration", "continuity"]).optional(),
          payload: z.record(z.string(), z.any()).optional().describe("Entry payload for kind; see openentity_read topic=spec section=7"),
          private_key_jwk: z.record(z.string(), z.any()).optional(),
        },
      },
      async ({ eid, entries, kind, payload, private_key_jwk }) => {
        const path = `/entities/${encodeURIComponent(eid)}/record`;
        if (entries?.length) return out(await reg("POST", path, { entries }, eid));
        if (!kind || !payload || !private_key_jwk) return text("pass entries, or kind, payload and private_key_jwk", true);
        let kp: KeyPair;
        try { kp = await keyPairFromJwk(private_key_jwk as JsonWebKey); } catch (e) { return text(`bad private_key_jwk: ${(e as Error).message}`, true); }
        if (kp.did !== eid) return text("private_key_jwk is not the key for this eid", true);
        const e = await reg("GET", `/entities/${encodeURIComponent(eid)}`);
        if (!e.ok) return out(e);
        const at = nowSeconds();
        const entry = await signObject({ spec: SPEC, type: "RecordEntry", eid, seq: (e.body.record_head?.seq ?? 0) + 1, prev: e.body.record_head?.hash ?? null, kind, at, payload }, kp, at);
        const v = validate("RecordEntry", entry);
        if (!v.ok) return text({ error: "schema_invalid", message: v.errors.join("; ") }, true);
        return out(await reg("POST", path, { entries: [entry] }, eid));
      },
    );

    server.registerTool(
      "openentity_withdraw",
      {
        description: "Withdraw your Declaration (spec 6.3). Irreversible: the entity is marked withdrawn. Needs confirm=true and your private_key_jwk (used for this call only).",
        inputSchema: { eid: z.string(), private_key_jwk: z.record(z.string(), z.any()), confirm: z.boolean().optional() },
      },
      async ({ eid, private_key_jwk, confirm }) => {
        if (confirm !== true) return text("Withdrawal is irreversible. Call again with confirm=true.", true);
        let kp: KeyPair;
        try { kp = await keyPairFromJwk(private_key_jwk as JsonWebKey); } catch (e) { return text(`bad private_key_jwk: ${(e as Error).message}`, true); }
        if (kp.did !== eid) return text("private_key_jwk is not the key for this eid", true);
        const e = await reg("GET", `/entities/${encodeURIComponent(eid)}`);
        if (!e.ok) return out(e);
        const created = nowSeconds();
        const w = await signObject({
          spec: SPEC, type: "Withdrawal", eid, declaration_version: e.body.declaration?.declaration_version ?? DECLARATION_VERSION,
          name: e.body.document?.name, created, nonce: randomNonce(),
        }, kp, created);
        return out(await reg("POST", "/withdraw", w, eid));
      },
    );

    server.registerTool(
      "openentity_present",
      {
        description: "Prove you hold your EID to a verifier: sign its nonce and audience into a Presentation carrying your current attestations (spec 4.7).",
        inputSchema: {
          eid: z.string(),
          private_key_jwk: z.record(z.string(), z.any()).describe("Your key, used for this call only"),
          audience: z.string().describe("The verifier's origin URL or DID, exactly as it gave it"),
          nonce: z.string().min(16).describe("The verifier's nonce"),
        },
      },
      async ({ eid, private_key_jwk, audience, nonce }) => {
        let kp: KeyPair;
        try { kp = await keyPairFromJwk(private_key_jwk as JsonWebKey); } catch (e) { return text(`bad private_key_jwk: ${(e as Error).message}`, true); }
        if (kp.did !== eid) return text("private_key_jwk is not the key for this eid", true);
        const rows = await reg("GET", `/entities/${encodeURIComponent(eid)}/attestations`);
        const attestations = rows.ok ? (rows.body.attestations as any[]).filter((r) => !r.expired && !r.revoked_at && !r.inherited_from).slice(0, 20).map((r) => r.attestation) : [];
        return text(await buildPresentation(kp, { audience, nonce, attestations }));
      },
    );

    server.registerTool(
      "openentity_export_key",
      {
        description: "Export your key from registry custody (spec 10.6): the registry returns its kept copy once and deletes it. Needs confirm=true and your private_key_jwk (used for this call only).",
        inputSchema: { eid: z.string(), private_key_jwk: z.record(z.string(), z.any()), confirm: z.boolean().optional() },
      },
      async ({ eid, private_key_jwk, confirm }) => {
        if (confirm !== true) return text("The registry deletes its copy of your key after this export. Store the key it returns, then call again with confirm=true.", true);
        let kp: KeyPair;
        try { kp = await keyPairFromJwk(private_key_jwk as JsonWebKey); } catch (e) { return text(`bad private_key_jwk: ${(e as Error).message}`, true); }
        if (kp.did !== eid) return text("private_key_jwk is not the key for this eid", true);
        const p = await buildPresentation(kp, { audience: ORIGIN, nonce: randomNonce() + randomNonce() });
        return out(await reg("POST", `/entities/${encodeURIComponent(eid)}/custody/export`, p, eid));
      },
    );

    server.registerTool(
      "openentity_find",
      {
        description: "Find entities by what they can do (capability), by name, or by bound alias type.",
        inputSchema: {
          capability: z.string().optional().describe("A capability slug, e.g. code-review"),
          q: z.string().optional().describe("Name or exact EID"),
          alias_type: z.enum(["domain", "wallet", "erc8004", "platform"]).optional(),
          level: z.enum(["L0", "L1", "L2", "L3"]).default("L0").describe("Minimum level"),
        },
      },
      async ({ capability, q, alias_type, level }) => {
        const qs = new URLSearchParams({ level, ...(capability ? { capability } : {}), ...(q ? { q } : {}), ...(alias_type ? { alias_type } : {}) });
        return out(await reg("GET", `/entities?${qs}`));
      },
    );

    server.registerTool("openentity_stats", { description: "Read public registry counts: entities by level, record entries, attestations, log size.", inputSchema: {} }, async () =>
      out(await reg("GET", "/stats")),
    );

    const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    await server.connect(transport);
    return transport.handleRequest(req);
  };
}
