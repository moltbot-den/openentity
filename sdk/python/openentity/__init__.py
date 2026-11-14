"""The Open Entity SDK for Python. The public surface is `__all__`; tests/test_api.py pins it.

The names mirror the TypeScript SDK (@openentity/sdk) with snake_case for camelCase. Functions that exist in only one SDK are
listed in tests/test_api.py."""
from . import issuer  # noqa: F401
from .agent import Owner, pair
from .client import CLIENTS, DEFAULT_REGISTRY, DISPUTE_REASONS, adopt, dispute, find, present, record, rotate, withdraw
from .commerce import (cart_digest, cart_error, mandate_covers, mandate_digest, receipt_error, sign_receipt,  # noqa: F401
                       verify_agent_for_checkout, verify_mandate, verify_receipt, RAILS)
from .core import *  # noqa: F401,F403
from .core import __all__ as _core
from .errors import (REGISTRY_ERROR_CODES, HttpSigError, InvalidInputError, OpenEntityError, RegistryError,  # noqa: F401
                     VerificationError)
from .httpsig import http_sig_base, sign_request, verify_request, verify_response
from .identity import Identity
from .issuer import (A2A_EXTENSION_URI, a2a_extension, agent_card, build_did_document, build_openentity_json, sign_attestation,
                     sign_revocation)
from .owner import approval_digest, payload_digest, verify_approval, verify_key_log
from .pair import pair_sas
from .report import TrustReport, clear_trust_cache, did_web_resolver, trust
from .schema import validate

__version__ = "1.1.0"

__all__ = sorted([
    *_core, "CLIENTS", "DEFAULT_REGISTRY", "DISPUTE_REASONS", "adopt", "dispute", "find", "present", "record", "rotate", "withdraw",
    "REGISTRY_ERROR_CODES", "HttpSigError", "InvalidInputError", "OpenEntityError", "RegistryError", "VerificationError",
    "http_sig_base", "sign_request", "verify_request", "verify_response", "Identity", "A2A_EXTENSION_URI", "a2a_extension", "agent_card", "build_did_document",
    "build_openentity_json", "sign_attestation", "sign_revocation", "TrustReport", "clear_trust_cache", "did_web_resolver", "trust",
    "cart_digest", "cart_error", "mandate_covers", "mandate_digest", "receipt_error", "sign_receipt", "verify_agent_for_checkout",
    "verify_mandate", "verify_receipt", "RAILS",
    "validate", "approval_digest", "payload_digest", "verify_approval", "verify_key_log", "pair_sas", "Owner", "pair",
])
