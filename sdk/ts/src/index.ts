// Reference TypeScript SDK for the Open Entity Identity Standard (OEIS-1).
// Runs unchanged in Node 22.13+ and Cloudflare Workers: WebCrypto Ed25519 for signing,
// @noble for hashing, verification and secp256k1. No node: imports.
// This file is the public surface: only the names listed here are exported (test/api.test.ts pins them).
export { SPEC, DECLARATION_VERSION, DECLARATION_TEXT, DECLARATION_SHA256, canonicalize, parseJson, sha256, sha256Hex, base58btcEncode, base58btcDecode, randomNonce, nowSeconds, type KeyPair, keyPairFromJwk, generateKeyPair, keyPairFromSeed, didKeyFromPublicKey, publicKeyFromDidKey, verificationMethodId, normalizeEid, type Proof, type Resolver, hashData, signProof, signObject, verifyProof, verifyObject, eip712Digest, recoverEip712 } from "./core.ts";
export { buildDocument, buildDeclaration, successorDocument, buildRotation, recordEntryHash, validate, checkTimestamp, mintStamp, checkStamp, buildPresentation, verifyPresentation, A2A_EXTENSION_URI, a2aExtension, agentCard, signAttestation, signRevocation, buildDidDocument, buildOpenEntityJson } from "./objects.ts";
export { rotate, CLIENTS, type Client, adopt, type TrustReport, clearTrustCache, didWebResolver, trust } from "./registry.ts";
export { leafHash, nodeHash, merkleRoot, inclusionProof, verifyInclusion, consistencyProof, verifyConsistency, logLeaf, checkpointBody, signNote, noteVkey, verifyNote } from "./merkle.ts";
export { DEFAULT_REGISTRY, DISPUTE_REASONS, type DisputeReason, withdraw, record, dispute, find, present } from "./client.ts";
export { OpenEntityError, HttpSigError, type RegistryErrorCode, type LocalErrorCode } from "./errors.ts";
export { httpSigBase, signRequest, verifyRequest } from "./httpsig.ts";
