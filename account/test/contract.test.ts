import { readFileSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";
import { parse } from "yaml";
import { expect, test } from "vitest";
import { createApp } from "../src/app.ts";
import { publicKey } from "../src/keys.ts";
import { rpFor } from "../src/passkey.ts";
import { pgliteDb } from "./helpers.ts";

const spec = parse(readFileSync(new URL("../openapi.yaml", import.meta.url), "utf8"));
const jwk = (k: { publicKey: import("node:crypto").KeyObject }) => k.publicKey.export({ format: "jwk" }) as any;
const app = createApp({
  stage: "staging", host: "staging.account.openentity.org", db: await pgliteDb(), pepper: "p", sendCode: async () => {},
  keys: {
    token: await publicKey(jwk(generateKeyPairSync("ec", { namedCurve: "P-256" })), async () => new Uint8Array(64)),
    did: await publicKey(jwk(generateKeyPairSync("ed25519")), async () => new Uint8Array(64)),
    close: await publicKey(jwk(generateKeyPairSync("ec", { namedCurve: "P-256" })), async () => new Uint8Array(64)),
  },
  rp: rpFor("staging.account.openentity.org"), apple: { native: [], web: [] }, google: [], androidFingerprints: [], signinOpen: true, web: {},
});

test("every route the service answers is in the frozen contract, with the same method", () => {
  const served = app.routes.filter((r) => r.method !== "ALL").map((r) => `${r.method} ${r.path.replace(/:([A-Za-z_]+)/g, "{$1}")}`);
  const contract = new Set(Object.entries(spec.paths as Record<string, Record<string, unknown>>).flatMap(([p, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${p}`)));
  expect(served.length).toBeGreaterThan(15);
  for (const r of served) expect(contract, r).toContain(r);
});

test("the contract names the four product signers, both environments and the service key profile", () => {
  const text = readFileSync(new URL("../openapi.yaml", import.meta.url), "utf8");
  for (const s of ["did:web:moltbotden.com", "did:web:securemyagent.ai", "did:web:api.agentsecretstore.com", "did:web:api.clawgrc.com", "did:web:staging.account.openentity.org", "ECC_NIST_EDWARDS25519"]) expect(text).toContain(s);
  expect(Object.keys(spec.components.securitySchemes)).toEqual(expect.arrayContaining(["ownerBearer", "webSession", "agentSignature", "productSignature", "accountSignature"]));
});
