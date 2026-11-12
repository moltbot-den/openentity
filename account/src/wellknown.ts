// Documents the service publishes at /.well-known (openapi.yaml, "Well-known").
import type { JWK } from "jose";
import { didKeyFromPublicKey } from "@openentity/sdk";
import type { SigningKey } from "./keys.ts";

export const BUNDLE_ID = "org.openentity.app";
/** The four product DIDs: token audiences, the only product signers, and the targets of signed events. */
export const PRODUCT_DIDS = ["did:web:moltbotden.com", "did:web:securemyagent.ai", "did:web:api.agentsecretstore.com", "did:web:api.clawgrc.com"];
export const APP_ID = `7R835D5LDZ.${BUNDLE_ID}`; // Team ID . bundle ID

/** Passkeys (webcredentials) and universal links under /app/ for the OpenEntity app. Served as application/json, never redirected. */
export const aasa = () => ({
  applinks: { details: [{ appIDs: [APP_ID], components: [{ "/": "/app/*", comment: "sign-in returns and deep links" }] }] },
  webcredentials: { apps: [APP_ID] },
});

/** Digital Asset Links for the Android app: App Links and passkeys. Null until the Play signing fingerprints exist. */
export const assetlinks = (sha256Fingerprints: string[]) => sha256Fingerprints.length
  ? [{
      relation: ["delegate_permission/common.handle_all_urls", "delegate_permission/common.get_login_creds"],
      target: { namespace: "android_app", package_name: BUNDLE_ID, sha256_cert_fingerprints: sha256Fingerprints },
    }]
  : null;

export const jwks = (keys: SigningKey[]) => ({ keys: keys.map((k) => ({ ...k.jwk, kid: k.kid, alg: "ES256", use: "sig" })) });

export const openidConfiguration = (host: string) => ({
  issuer: `https://${host}`,
  jwks_uri: `https://${host}/.well-known/jwks.json`,
  token_endpoint: `https://${host}/v1/token`,
  revocation_endpoint: `https://${host}/v1/revoke`,
  grant_types_supported: ["refresh_token", "urn:openentity:login_code"],
  token_endpoint_auth_methods_supported: ["none"],
  response_types_supported: [],
});

/**
 * did:web:<host>. The Ed25519 key signs RFC 9421 requests and envelopes to products (authentication, assertionMethod).
 * The P-256 close keys, current and every retired one, sign key log `close` entries (assertionMethod): verifiers pass
 * them as serviceKeys. Access tokens are verified from jwks.json, not from here. Fragments are RFC 7638 thumbprints.
 */
export function didDocument(host: string, o: { did: SigningKey[]; close: SigningKey[] }) {
  const id = `did:web:${host}`;
  const ed = o.did.map((k) => ({
    id: `${id}#${k.kid}`, type: "Multikey", controller: id,
    publicKeyMultibase: didKeyFromPublicKey(Buffer.from(k.jwk.x!, "base64url")).slice("did:key:".length),
  }));
  const ec = o.close.map((k) => ({ id: `${id}#${k.kid}`, type: "JsonWebKey", controller: id, publicKeyJwk: k.jwk as JWK }));
  return {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1", "https://w3id.org/security/jwk/v1"],
    id,
    verificationMethod: [...ed, ...ec],
    authentication: ed.map((v) => v.id),
    assertionMethod: [...ed, ...ec].map((v) => v.id),
  };
}
