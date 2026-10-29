import { describe, expect, it } from "vitest";
import { generateKeyPair, nowSeconds, signObject, type KeyPair } from "../src/sdk.ts";
import { E, adopted, call, write } from "./helpers.ts";

const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");
const attest = (issuer: KeyPair, subject: string, claim_type: string) =>
  signObject({ spec: "openentity/1.0", type: "Attestation", issuer: issuer.did, subject, claim_type, claim: { upheld: true }, created: iso(Date.now()), expires: iso(Date.now() + 86400_000) }, issuer);

describe("GET /entities sort and row columns (spec 10.2)", () => {
  it("sort=attested orders by unrevoked attestation count, ties newest; rows carry aliases, attestations and observers", async () => {
    const a = await adopted("A"), b = await adopted("B"), c = await adopted("C");
    await E.db.run("UPDATE entities SET created = $1 WHERE eid = $2", ["2026-01-01T00:00:00Z", a.kp.did]);
    await E.db.run("UPDATE entities SET created = $1 WHERE eid = $2", ["2026-01-02T00:00:00Z", b.kp.did]);
    await E.db.run("UPDATE entities SET created = $1 WHERE eid = $2", ["2026-01-03T00:00:00Z", c.kp.did]);
    const o1 = await generateKeyPair(), o2 = await generateKeyPair(), stranger = await generateKeyPair();
    for (const o of [o1, o2]) await E.db.run("INSERT INTO observers (did, name, accredited_at, bootstrap) VALUES ($1, 'Obs', $2, 1)", [o.did, nowSeconds()]);
    await E.db.run("INSERT INTO aliases (eid, type, value, status, verified_at, log_index) VALUES ($1, 'domain', 'a.example', 'verified', $2, 1), ($1, 'wallet', 'w', 'pending', NULL, NULL)", [a.kp.did, nowSeconds()]);

    // A: two observers plus one stranger (an attestation, not an observer). B: one, revoked. C: none.
    for (const o of [o1, o2, stranger]) expect((await write("POST", "/attestations", o.did, await attest(o, a.kp.did, "consistency"))).status).toBe(201);
    const posted = await write("POST", "/attestations", o1.did, await attest(o1, b.kp.did, "consistency"));
    expect(posted.status).toBe(201);
    const rev = await signObject({ spec: "openentity/1.0", type: "Revocation", issuer: o1.did, attestation_sha256: posted.body.sha256, created: nowSeconds() }, o1);
    expect((await write("POST", "/attestations", o1.did, rev)).status).toBe(201);

    const list = async (sort?: string) => (await call("GET", `/entities?level=0${sort ? `&sort=${sort}` : ""}`)).body.entities as any[];
    const mine = (rows: any[]) => rows.map((r) => r.eid).filter((e) => [a.kp.did, b.kp.did, c.kp.did].includes(e));
    expect(mine(await list())).toEqual([c.kp.did, b.kp.did, a.kp.did]);
    expect(mine(await list("newest"))).toEqual([c.kp.did, b.kp.did, a.kp.did]);
    expect(mine(await list("attested"))).toEqual([a.kp.did, c.kp.did, b.kp.did]); // B's only attestation is revoked: ties with C, C is newer
    expect((await list("attested")).find((r) => r.eid === a.kp.did)).toMatchObject({ aliases: ["domain"], attestations: 3, observers: 2 });
    expect((await list()).find((r) => r.eid === c.kp.did)).toMatchObject({ aliases: [], attestations: 0, observers: 0 });
    expect((await call("GET", "/entities?sort=bogus")).status).toBe(422);
  });
});
