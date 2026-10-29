/** Error codes the registry answers with (`{ error, message }`), as of this release. Any string is possible: a newer registry may add codes. */
export type RegistryErrorCode =
  | "alias_exists" | "alias_proof_invalid" | "already_redacted" | "already_revoked" | "already_withdrawn" | "attestation_not_found"
  | "bad_email" | "bad_json" | "bad_sort" | "bad_token" | "bad_tree_size" | "batch_too_large" | "continuity_proof_missing"
  | "custody_unavailable" | "declaration_exists" | "declaration_hash_mismatch" | "declaration_not_found" | "dispute_exists"
  | "document_required" | "eid_mismatch" | "entity_exists" | "entity_not_found" | "entry_hash_mismatch" | "entry_not_found"
  | "expires_invalid" | "invalid_client" | "no_checkpoint" | "no_custodial_copy" | "nonce_reused" | "not_incorporated" | "not_issuer"
  | "object_not_about_subject" | "object_not_found" | "presentation_invalid" | "previous_has_successor" | "rate_limited"
  | "record_chain_broken" | "recovery_alias_required" | "schema_invalid" | "seq_invalid" | "signature_invalid" | "snapshot_not_found"
  | "stamp_invalid" | "stamp_required" | "stamp_reused" | "subscribe_failed" | "subscribe_unavailable" | "successor_has_predecessor"
  | "tile_not_found" | "timestamp_invalid" | "too_large" | "turnstile_failed" | "unresolvable" | "unsupported_method"
  | "updated_not_increasing";

/** Codes the SDK raises itself. `registry_error` is a non-2xx answer without a registry error body. */
export type LocalErrorCode = "invalid_input" | "verification_failed" | "registry_error";

/**
 * Every error the SDK throws on purpose. `code` is a registry error code when the registry refused the request (`status` is the
 * HTTP status then), a local code otherwise, or the RFC 9421 failure code for `HttpSigError`. Plain `Error` handlers keep working.
 */
export class OpenEntityError extends Error {
  code: RegistryErrorCode | LocalErrorCode | (string & {});
  status?: number;
  constructor(code: string, message: string, status?: number) {
    super(message);
    this.name = "OpenEntityError";
    this.code = code;
    this.status = status;
  }
}

/** RFC 9421 verification failure; `code` is the failure reason, such as `bad_signature` or `digest_mismatch`. */
export class HttpSigError extends OpenEntityError {
  constructor(code: string) {
    super(code, code);
    this.name = "HttpSigError";
  }
}

/** @internal The error for a non-2xx registry answer: the registry's own code when the body carries one. */
export function registryError(status: number, where: string, text: string): OpenEntityError {
  let code = "registry_error";
  try {
    const e = JSON.parse(text)?.error;
    if (typeof e === "string") code = e;
  } catch {}
  return new OpenEntityError(code, `registry ${status} for ${where}: ${text.slice(0, 200)}`, status);
}
