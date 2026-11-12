// Passkeys on RP ID account.openentity.org (staging: staging.account.openentity.org) through @simplewebauthn/server.
// User verification is required everywhere. Only ES256 (-7): a passkey is also a key log credential, which is P-256.
import {
  generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse,
  type AuthenticationResponseJSON, type RegistrationResponseJSON, type WebAuthnCredential,
} from "@simplewebauthn/server";
import { cose, decodeCredentialPublicKey } from "@simplewebauthn/server/helpers";
import { calculateJwkThumbprint, type JWK } from "jose";
import { fail } from "./http.ts";

export interface Rp { id: string; origins: string[] }
export const TIMEOUT_MS = 300_000;

/** Web origin, plus the Android app's android:apk-key-hash origins once the signing certificates are known. */
export const rpFor = (host: string, androidOrigins: string[] = []): Rp => ({ id: host, origins: [`https://${host}`, ...androidOrigins] });

/** Discoverable sign-in: no allowCredentials, the authenticator offers the user's passkeys for this RP. */
export const authenticationOptions = (rp: Rp) => generateAuthenticationOptions({ rpID: rp.id, userVerification: "required", timeout: TIMEOUT_MS });

export const registrationOptions = (rp: Rp, o: { accountId: string; userName: string; exclude?: { id: string; transports?: string[] }[] }) =>
  generateRegistrationOptions({
    rpName: "OpenEntity",
    rpID: rp.id,
    userName: o.userName,
    userDisplayName: o.userName,
    userID: new TextEncoder().encode(o.accountId),
    attestationType: "none",
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
    supportedAlgorithmIDs: [cose.COSEALG.ES256],
    excludeCredentials: o.exclude ?? [],
    timeout: TIMEOUT_MS,
  });

export interface Registered {
  credential: WebAuthnCredential;
  aaguid: string;
  backedUp: boolean;
  /** The public key as the key log carries it, with its RFC 7638 thumbprint. */
  jwk: JWK;
  keyId: string;
}

const rejected = (e: unknown): never => fail(401, "passkey_invalid", `passkey response rejected: ${(e as Error).message}`);

export async function verifyRegistration(rp: Rp, response: RegistrationResponseJSON, expectedChallenge: string): Promise<Registered> {
  const v = await verifyRegistrationResponse({
    response, expectedChallenge, expectedOrigin: rp.origins, expectedRPID: rp.id,
    requireUserVerification: true, supportedAlgorithmIDs: [cose.COSEALG.ES256],
  }).catch(rejected);
  if (!v.verified) return rejected(new Error("not verified"));
  const { credential, aaguid, credentialBackedUp } = v.registrationInfo;
  const k = decodeCredentialPublicKey(credential.publicKey) as unknown as Map<number, number | Uint8Array>;
  const coord = (label: number) => Buffer.from(k.get(label) as Uint8Array).toString("base64url");
  if (k.get(cose.COSEKEYS.kty) !== cose.COSEKTY.EC2 || k.get(cose.COSEKEYS.crv) !== cose.COSECRV.P256) return rejected(new Error("not a P-256 key"));
  const jwk: JWK = { kty: "EC", crv: "P-256", x: coord(cose.COSEKEYS.x), y: coord(cose.COSEKEYS.y) };
  return { credential, aaguid, backedUp: credentialBackedUp, jwk, keyId: await calculateJwkThumbprint(jwk, "sha256") };
}

/** Returns the new signature counter; the library rejects a counter that went backwards. */
export async function verifyAuthentication(rp: Rp, response: AuthenticationResponseJSON, expectedChallenge: string, credential: WebAuthnCredential): Promise<number> {
  if (response.id !== credential.id) return rejected(new Error("credential mismatch"));
  const v = await verifyAuthenticationResponse({
    response, expectedChallenge, expectedOrigin: rp.origins, expectedRPID: rp.id, credential, requireUserVerification: true,
  }).catch(rejected);
  if (!v.verified) return rejected(new Error("not verified"));
  return v.authenticationInfo.newCounter;
}
