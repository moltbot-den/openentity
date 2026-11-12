export { SPEC, DECLARATION_VERSION, DECLARATION_TEXT, DECLARATION_SHA256, canonicalize, parseJson, sha256, sha256Hex, base58btcEncode, base58btcDecode, randomNonce, nowSeconds, type KeyPair, keyPairFromJwk, generateKeyPair, keyPairFromSeed, didKeyFromPublicKey, publicKeyFromDidKey, verificationMethodId, normalizeEid, type Proof, type Resolver, hashData, signProof, signObject, verifyProof, verifyObject, eip712Digest, recoverEip712 } from "./core.ts";
export { buildDocument, buildDeclaration, successorDocument, buildRotation, recordEntryHash, validate, checkTimestamp, mintStamp, checkStamp, buildPresentation, verifyPresentation, A2A_EXTENSION_URI, a2aExtension, agentCard, signAttestation, signRevocation, buildDidDocument, buildOpenEntityJson } from "./objects.ts";
export { rotate, CLIENTS, type Client, adopt, type TrustReport, clearTrustCache, didWebResolver, trust } from "./registry.ts";
export { leafHash, nodeHash, merkleRoot, inclusionProof, verifyInclusion, consistencyProof, verifyConsistency, logLeaf, checkpointBody, signNote, noteVkey, verifyNote } from "./merkle.ts";
export { DEFAULT_REGISTRY, DISPUTE_REASONS, type DisputeReason, withdraw, record, dispute, find, present } from "./client.ts";
export { OpenEntityError, HttpSigError, type RegistryErrorCode, type LocalErrorCode } from "./errors.ts";
export { httpSigBase, signRequest, verifyRequest, verifyResponse } from "./httpsig.ts";
export { approvalDigest, payloadDigest, verifyApproval, verifyKeyLog, type Credential, type KeyLogState, type KeyLogResult, type KeyLogOptions, type KeyLogError, type ApprovalOptions, type ApprovalResult, type ApprovalError } from "./owner.ts";
export { pairSas } from "./pair.ts";
