// Live proof, not part of the suite: signs through the deployed KMS keys and verifies against what the service publishes.
//   AWS_PROFILE=openentity npx tsx account/test/kms-live.ts staging.account.openentity.org OpenEntityAccountStaging
import { execFileSync } from "node:child_process";
import { createPublicKey, verify } from "node:crypto";
import { KMSClient } from "@aws-sdk/client-kms";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { kmsEd25519, kmsEs256, kmsKey, signJwt } from "../src/keys.ts";

const [host, stack] = process.argv.slice(2);
const outputs = JSON.parse(execFileSync("aws", ["cloudformation", "describe-stacks", "--stack-name", stack, "--region", "us-east-1", "--output", "json"], { encoding: "utf8" })).Stacks[0].Outputs;
const out = (k: string) => outputs.find((o: any) => o.OutputKey === k).OutputValue;
const kms = new KMSClient({ region: "us-east-1" });

// ES256: 20 tokens, so DER signatures with 31-, 32- and 33-byte integers all pass through the conversion.
const token = await kmsKey(kms, out("TokenKeyArn"), kmsEs256);
const jwks = createRemoteJWKSet(new URL(`https://${host}/.well-known/jwks.json`));
for (let i = 0; i < 20; i++) {
  const jwt = await signJwt(token, { typ: "at+jwt" }, { iss: `https://${host}`, aud: "did:web:kms-live.example", sub: `proof-${i}`, exp: Math.floor(Date.now() / 1000) + 60 });
  await jwtVerify(jwt, jwks, { algorithms: ["ES256"], issuer: `https://${host}`, audience: "did:web:kms-live.example", typ: "at+jwt" });
}
console.log(`ES256 through KMS: 20 JWTs verify against https://${host}/.well-known/jwks.json (kid ${token.kid})`);

// Ed25519: a signature from the KMS key verifies against the Multikey in did.json.
const did = await kmsKey(kms, out("DidKeyArn"), kmsEd25519);
const doc = await (await fetch(`https://${host}/.well-known/did.json`)).json();
const vm = doc.verificationMethod.find((v: any) => v.id === `did:web:${host}#${did.kid}`);
if (!vm) throw new Error("did.json does not publish the KMS Ed25519 key");
const msg = new TextEncoder().encode(`"@method": POST\n"@signature-params": ("@method");keyid="${vm.id}"`);
const pub = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: did.jwk.x! }, format: "jwk" });
if (!verify(null, msg, pub, await did.sign(msg))) throw new Error("Ed25519 signature from KMS does not verify");
console.log(`Ed25519 through KMS: verifies against ${vm.id} (${vm.publicKeyMultibase.slice(0, 12)}...)`);
