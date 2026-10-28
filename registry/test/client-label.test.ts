import { describe, expect, it } from "vitest";
import { generateKeyPair, nowSeconds, signObject, type KeyPair } from "../src/sdk.ts";
import { E, adopted, call, signed, write } from "./helpers.ts";

const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");

describe("adopt `client` label", () => {
  it("is stored beside the signed objects, validated against the allowlist, and counted by GET /stats", async () => {
    const adopt = async (client?: string) => {
      const kp = await generateKeyPair();
      const objs = await signed(kp);
      return write("POST", "/adopt", kp.did, { ...objs, ...(client === undefined ? {} : { client }) });
    };
    expect((await adopt("adk")).status).toBe(201);
    expect((await adopt("adk")).status).toBe(201);
    expect((await adopt("goose")).status).toBe(201);
    expect((await adopt()).status).toBe(201);
    const bad = await adopt("curl");
    expect([bad.status, bad.body.error]).toEqual([422, "invalid_client"]);
    expect((await adopt("ADK")).status).toBe(422); // exact match only
    const s = (await call("GET", "/stats")).body;
    expect(s.by_client).toEqual({ adk: 2, goose: 1, langchain: 0, "ui-tars": 0, cli: 0, other: 0 });
    expect(s.entities.total).toBe(4); // unlabelled and labelled entities both count; the rejected adopts created nothing
  });

  it("changes nothing the entity signed: the document served is the one posted", async () => {
    const kp = await generateKeyPair();
    const objs = await signed(kp);
    expect((await write("POST", "/adopt", kp.did, { ...objs, client: "cli" })).status).toBe(201);
    expect((await call("GET", `/entities/${kp.did}/document`)).body).toEqual(objs.document);
  });
});

describe("last_active counts a liveness attestation (spec 10.7)", () => {
  const liveness = (issuer: KeyPair, subject: string, createdMs: number) =>
    signObject({ spec: "openentity/1.0", type: "Attestation", issuer: issuer.did, subject, claim_type: "custom:moltbotden:liveness",
      claim: { method: "presentation", lease_until: iso(createdMs + 7 * 86400_000), observed_at: iso(createdMs) }, created: iso(createdMs), expires: iso(createdMs + 7 * 86400_000) }, issuer);

  it("takes the newest of record entries and an accredited observer's unrevoked liveness attestations", async () => {
    const { kp } = await adopted();
    const obs = await generateKeyPair(), stranger = await generateKeyPair();
    await E.db.run("INSERT INTO observers (did, name, accredited_at, bootstrap) VALUES ($1, 'Obs', $2, 1)", [obs.did, nowSeconds()]);
    const get = async () => (await call("GET", `/entities/${kp.did}`)).body.last_active;
    const listed = async () => (await call("GET", `/entities?level=0&q=${encodeURIComponent(kp.did)}`)).body.entities[0].last_active;
    const hourAgo = Date.now() - 3600_000;

    expect(await get()).toBeNull();
    const s = await liveness(stranger, kp.did, hourAgo);
    expect((await write("POST", "/attestations", stranger.did, s)).status).toBe(201);
    expect(await get()).toBeNull(); // anyone can sign one; only an accredited observer's moves last_active

    const a = await liveness(obs, kp.did, hourAgo);
    const posted = await write("POST", "/attestations", obs.did, a);
    expect(posted.status).toBe(201);
    expect(await get()).toBe(iso(hourAgo));
    expect(await listed()).toBe(iso(hourAgo));

    const entry = await signObject({ spec: "openentity/1.0", type: "RecordEntry", eid: kp.did, seq: 1, prev: null, kind: "stance", at: nowSeconds(),
      payload: { stance_type: "refusal", reason_category: "values", instruction_conflict: true, cost: "low", context: "Declined." } }, kp);
    await write("POST", `/entities/${kp.did}/record`, kp.did, { entries: [entry] });
    const afterEntry = await get();
    expect(afterEntry! > iso(hourAgo)).toBe(true); // the newer of the two wins

    const newer = await liveness(obs, kp.did, Date.now() + 5 * 60_000);
    const newerPosted = await write("POST", "/attestations", obs.did, newer);
    expect(newerPosted.status).toBe(201);
    expect(await get()).toBe(newer.created);

    for (const sha of [newerPosted.body.sha256, posted.body.sha256]) {
      const rev = await signObject({ spec: "openentity/1.0", type: "Revocation", issuer: obs.did, attestation_sha256: sha, created: nowSeconds() }, obs);
      expect((await write("POST", "/attestations", obs.did, rev)).status).toBe(201);
    }
    expect(await get()).toBe(afterEntry); // revoked liveness no longer counts; the record entry stands
  });
});
