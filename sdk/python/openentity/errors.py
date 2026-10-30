"""Every error the SDK raises on purpose derives from OpenEntityError and carries a `code`.

REGISTRY_ERROR_CODES are the codes the registry answers with. `RegistryError.code` is one of them when the registry refused a
request, or "registry_error" for a non-2xx answer without an error body. Local failures use "invalid_input" and
"verification_failed"; HttpSigError uses the RFC 9421 failure reason. InvalidInputError and VerificationError are also
ValueErrors, so code written against 0.5 (`except ValueError`) keeps working.
"""

REGISTRY_ERROR_CODES = frozenset("""
alias_exists alias_proof_invalid already_redacted already_revoked already_withdrawn attestation_not_found bad_email bad_json
bad_offset bad_query bad_sort bad_token bad_tree_size batch_too_large continuity_proof_missing custody_unavailable declaration_exists
declaration_hash_mismatch declaration_not_found dispute_exists document_required eid_mismatch entity_exists entity_not_found
entry_hash_mismatch entry_not_found expires_invalid invalid_client no_checkpoint no_custodial_copy nonce_reused not_incorporated
not_issuer object_not_about_subject object_not_found presentation_invalid previous_has_successor rate_limited record_chain_broken
recovery_alias_required schema_invalid seq_invalid signature_invalid snapshot_not_found stamp_invalid stamp_required stamp_reused
subscribe_failed subscribe_unavailable successor_has_predecessor tile_not_found timestamp_invalid too_large turnstile_failed
unresolvable unsupported_method updated_not_increasing
""".split())


class OpenEntityError(Exception):
    code: str = "error"

    def __init__(self, message: str = "", code: str | None = None):
        super().__init__(message)
        if code is not None:
            self.code = code


class InvalidInputError(OpenEntityError, ValueError):
    code = "invalid_input"


class VerificationError(OpenEntityError, ValueError):
    code = "verification_failed"


class RegistryError(OpenEntityError):
    """A non-2xx registry answer: `status`, `body` (parsed JSON when it was JSON) and `code`."""

    def __init__(self, status: int, body):
        code = body.get("error") if isinstance(body, dict) else None
        super().__init__(f"registry returned {status}: {body}", code if isinstance(code, str) else "registry_error")
        self.status, self.body = status, body


class HttpSigError(OpenEntityError):
    """RFC 9421 verification failure; `code` is the reason, such as "bad_signature" or "digest_mismatch"."""

    def __init__(self, code: str):
        super().__init__(code, code)
