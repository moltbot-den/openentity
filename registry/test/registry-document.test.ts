import { afterEach, describe, expect, it, vi } from "vitest";
import { validate, verifyObject } from "../src/sdk.ts";
import { registryKey } from "../src/log.ts";
import { resolver } from "../src/aliases.ts";
import { E, call, mockFetch } from "./helpers.ts";

afterEach(() => vi.restoreAllMocks());

const DID = "did:web:openentity.org";

describe("the registry's own Entity Document (spec 10.1, 11.1)", () => {
  it("is a valid EntityDocument signed by the did:web key, operated by Moltbot Den, logged once", async () => {
    const kp = await registryKey(E);
    const vm = `${DID}#key-1`;
    mockFetch({ "openentity.org/.well-known/did.json": () => ({ id: DID, verificationMethod: [{ id: vm, type: "Multikey", controller: DID, publicKeyMultibase: kp.did.slice(8) }] }) });

    const [a, b] = await Promise.all([call("GET", `/entities/${DID}/document`), call("GET", `/entities/${DID}/document`)]);
    expect([a.status, b.status]).toEqual([200, 200]);
    expect(b.body).toEqual(a.body);
    const doc = a.body;
    expect(validate("EntityDocument", doc)).toEqual({ ok: true, errors: [] });
    expect(doc).toMatchObject({ eid: DID, seq: 1, operator: { kind: "organization", name: "Moltbot Den", custody: "operator" } });
    expect(doc.keys).toEqual([{ id: vm, type: "Multikey", publicKeyMultibase: kp.did.slice(8) }]);
    const sig = await verifyObject(doc, resolver);
    expect(sig).toMatchObject({ ok: true, signer: DID });

    // A third read after the first two returns the same stored object; the log holds exactly one leaf for it.
    expect((await call("GET", `/entities/${DID}/document`)).body).toEqual(doc);
    const leaves = await E.db.all("SELECT type FROM log_leaves WHERE eid = $1 UNION ALL SELECT type FROM log_pending WHERE eid = $1", [DID]);
    expect(leaves).toEqual([{ type: "EntityDocument" }]);
  });
});
