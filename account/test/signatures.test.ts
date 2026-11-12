import { generateKeyPairSync } from "node:crypto";
import { didKeyFromPublicKey, signRequest, verifyRequest } from "@openentity/sdk";
import { expect, test } from "vitest";
import { createApp } from "../src/app.ts";
import { retryOutbox, sendEvent } from "../src/outbound.ts";
import { productSigned } from "../src/rfc9421.ts";
import { SERVICE_DID, caller, testDeps } from "./helpers.ts";

// A throwaway Ed25519 key standing in for Moltbot Den's product key, published in a fake did.json.
const product = generateKeyPairSync("ed25519");
const seed = new Uint8Array(product.privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32));
const pub = new Uint8Array(product.publicKey.export({ format: "der", type: "spki" }).subarray(-32));
const DEN = "did:web:moltbotden.com";
const denDoc = { id: DEN, verificationMethod: [{ id: `${DEN}#key-1`, type: "Multikey", controller: DEN, publicKeyMultibase: didKeyFromPublicKey(pub).slice(8) }], authentication: [`${DEN}#key-1`] };

const sent: { url: string; init: RequestInit }[] = [];
let productStatus = 204;
const fakeFetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
  const url = String(input);
  if (url === "https://moltbotden.com/.well-known/did.json") return Response.json(denDoc);
  sent.push({ url, init });
  return new Response(null, { status: productStatus });
}) as typeof fetch;

const d = await testDeps({ fetch: fakeFetch });
const app = createApp(d), call = caller(app);
app.post("/test/product", async (c) => c.json(await productSigned(c, d)));

const signed = async (keyid: string, body: string, key = seed) =>
  signRequest({ method: "POST", url: `https://${d.host}/test/product`, body: new TextEncoder().encode(body), privateKey: key, did: keyid });

test("productSigned: a product's did:web key verifies once; replays, other signers and changed bodies are refused", async () => {
  const body = JSON.stringify({ hello: "den" });
  const h = await signed(`${DEN}#key-1`, body);
  expect((await call("POST", "/test/product", body, h)).body).toEqual({ did: DEN });
  expect((await call("POST", "/test/product", body, h)).body.error).toBe("signature_replayed");
  expect((await call("POST", "/test/product", JSON.stringify({ hello: "evil" }), await signed(`${DEN}#key-1`, body))).body).toMatchObject({ error: "signature_invalid", message: "digest_mismatch" });
  expect((await call("POST", "/test/product", body, await signed("did:web:evil.example#key-1", body))).body.error).toBe("unknown_signer");
  const agent = generateKeyPairSync("ed25519");
  const agentSeed = new Uint8Array(agent.privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32));
  const agentDid = didKeyFromPublicKey(new Uint8Array(agent.publicKey.export({ format: "der", type: "spki" }).subarray(-32)));
  expect((await call("POST", "/test/product", body, await signed(agentDid, body, agentSeed))).body.error).toBe("unknown_signer");
});

test("sendEvent: an AccountEvent signed with the service key that products verify from did.json; failures wait in the outbox", async () => {
  productStatus = 204;
  expect(await sendEvent(d, DEN, "agent.paused", { agent_did: "did:key:z6Mk1", seq: 1 })).toBe(true);
  const { url, init } = sent.at(-1)!;
  expect(url).toBe("https://api.moltbotden.com/v1/oe/events");
  const doc = (await call("GET", "/.well-known/did.json")).body;
  const v = await verifyRequest({
    method: "POST", url, headers: init.headers as Record<string, string>, body: init.body as Uint8Array,
    allowDidWeb: [SERVICE_DID], fetchJson: async () => doc,
  });
  expect(v.keyid).toBe(`${SERVICE_DID}#${d.keys.did.kid}`);
  const event = JSON.parse(new TextDecoder().decode(init.body as Uint8Array));
  expect(event).toMatchObject({ id: expect.stringMatching(/^evt_/), type: "agent.paused", data: { seq: 1 } });

  productStatus = 503;
  expect(await sendEvent(d, DEN, "agent.resumed", { seq: 2 })).toBe(false);
  const row = await d.db.first<any>("SELECT * FROM outbox WHERE product = $1", [DEN]);
  expect(JSON.parse(row.body).type).toBe("agent.resumed");
  await d.db.run("UPDATE outbox SET next_at = 0");
  productStatus = 204;
  await retryOutbox(d);
  expect(await d.db.first("SELECT 1 FROM outbox")).toBeNull();
  expect(JSON.parse(new TextDecoder().decode(sent.at(-1)!.init.body as Uint8Array)).id).toBe(JSON.parse(row.body).id); // the same id, so products dedupe it

  productStatus = 400; // a refusal is dropped, not retried
  expect(await sendEvent(d, DEN, "agent.unlinked", {})).toBe(false);
  expect(await d.db.first("SELECT 1 FROM outbox")).toBeNull();
});
