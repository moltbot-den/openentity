import { readFile } from "node:fs/promises";
import { nowSeconds, parseJson, randomNonce, signObject, SPEC, validate, verifyPresentation } from "@openentity/sdk";
import { resolver } from "./did";
import { EXIT, usage } from "./errors";
import { Registry } from "./http";
import { loadEntity, regUrl, type Ctx, type Result } from "./store";

const REASONS = ["impersonation", "illegal_content", "inaccurate", "other"];

/** File a signed Dispute (spec 10.5) about another entity, or about one of its objects by `--object <sha256>`. */
export async function dispute({ v }: Ctx): Promise<Result> {
  if (!v.subject || !v.statement) throw usage(`dispute --subject <eid> [--object <sha256>] --reason ${REASONS.join("|")} --statement <text>`);
  if (!REASONS.includes(v.reason)) throw usage(`--reason must be one of: ${REASONS.join(", ")}`);
  if (v.object && !/^[0-9a-f]{64}$/.test(v.object)) throw usage("--object must be the 64-hex sha256 of the disputed object");
  const e = await loadEntity(v);
  const d = await signObject(
    { spec: SPEC, type: "Dispute", issuer: e.eid, subject: v.subject, ...(v.object ? { object_sha256: v.object } : {}), reason: v.reason, statement: v.statement, created: nowSeconds(), nonce: randomNonce() },
    e.kp,
  );
  const r = validate("Dispute", d);
  if (!r.ok) throw usage(`dispute invalid: ${r.errors.join("; ")}`);
  const res = await e.registry.send("POST", "/v1/disputes", d, e.eid);
  return { json: res, text: `dispute filed against ${v.subject}; the registry answers by ${res.answer_by}` };
}

/** Check a Presentation this verifier asked for, offline: signature, audience, nonce, freshness, carried attestations. */
export async function verifyPresentationCmd({ args, v }: Ctx): Promise<Result> {
  if (!args[0] || !v.audience || !v.nonce) throw usage("verify-presentation <file> --audience <this verifier's origin or DID> --nonce <the nonce you issued>");
  let p: any;
  try {
    p = parseJson(await readFile(args[0], "utf8"));
  } catch (e: any) {
    throw usage(`cannot read ${args[0]}: ${e.message}`);
  }
  const r = await verifyPresentation(p, { audience: String(v.audience), nonce: String(v.nonce), resolver });
  const lines = [
    ...r.errors.map((m) => `FAIL ${m}`),
    ...r.attestations.map((a) => `${a.ok ? "ok  " : "FAIL"} attestation ${a.claim_type} by ${a.issuer}${a.error ? `: ${a.error}` : ""}`),
    r.ok ? `VERIFIED ${r.eid}` : "VERIFICATION FAILED",
  ];
  return { json: r, text: lines.join("\n"), code: r.ok ? 0 : EXIT.VERIFY };
}

/** Directory search (spec 10.5): GET /v1/entities with the given filters. */
export async function find({ v }: Ctx): Promise<Result> {
  if (!v.capability && !v.q) throw usage("find --capability <slug> [--q <name or eid> --alias-type <type> --level L1]");
  const qs = new URLSearchParams();
  for (const [flag, param] of [["capability", "capability"], ["q", "q"], ["alias-type", "alias_type"], ["level", "level"]] as const) if (v[flag]) qs.set(param, String(v[flag]));
  const res = await new Registry(regUrl(v)).get(`/v1/entities?${qs}`);
  const rows: any[] = res.entities ?? [];
  const text = rows.length ? rows.map((x) => `${x.eid}  ${x.level ?? ""}  ${x.name}`).join("\n") + (res.next_page != null ? `\nmore: page ${res.next_page}` : "") : `no entities match${v.level ? "" : " (the directory lists L1 and above unless you pass --level L0)"}`;
  return { json: res, text };
}
