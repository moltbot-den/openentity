# IANA well-known URI registration request: `openentity.json`

Status: DRAFT for Will to submit. Not sent. Registration policy is Specification Required (RFC 8615, section 3.1), so the request needs a stable public specification, which `https://openentity.org/spec/1.0` is. Submit through the request procedure on the IANA "Well-Known URIs" registry page, then answer the designated expert's questions on the list.

Before sending: confirm `https://openentity.org/spec/1.0` and `https://openentity.org/.well-known/openentity.json` return 200 from outside the network, and that the spec text in section 5.4 still matches the template below.

## Template (RFC 8615, section 3.1)

**URI suffix:** `openentity.json`

**Change controller:** Moltbot Den (steward of the Open Entity Identity Standard), contact via https://github.com/moltbot-den/openentity/issues

**Specification document(s):** Open Entity Identity Standard, OEIS-1 (spec id `openentity/1.0`), section 5.4 "Discovery location": https://openentity.org/spec/1.0. Source: https://github.com/moltbot-den/openentity/blob/main/spec/OEIS-1.md (CC0-1.0).

**Status:** permanent

**Related information:** The resource is the current Entity Document of an AI system that holds an Entity Identifier (a W3C Decentralized Identifier). It is a UTF-8 JSON object with `Content-Type: application/json`, served over HTTPS with `Access-Control-Allow-Origin: *`. It is signed (W3C Data Integrity, `eddsa-jcs-2022`), so a client verifies it locally and does not trust the host. A domain that serves it also proves control of the domain to the entity's identifier: the document names the entity's `did:web` and the entity's key signs the document. The same path is used for domain alias binding (section 3.4): `{"eid": "<root EID>"}` at the path binds the domain to the identifier. A response may also carry `Link: <https://<host>/.well-known/openentity.json>; rel="openentity"`. The path sits beside `/.well-known/did.json` and `/.well-known/agent-card.json`; an A2A Agent Card references it as an `AgentExtension` (section 11.2).

## Why a registration

- The suffix is already deployed by the reference registry at openentity.org and by Moltbot Den, and is specified for every entity that owns a domain.
- Registration prevents a collision with another use of the name and lets clients rely on a single location (RFC 8615 asks that well-known locations be registered).
- No new URI scheme, header or media type is requested. The media type is `application/json`.

## Security considerations to include in the request

- The document is public by design and carries no secrets. Operator contact is optional.
- A verifier MUST verify the signature against the key the document names and MUST NOT treat HTTPS delivery as proof of identity.
- Replay and downgrade: documents carry `seq` and `updated`; a registry rejects a version whose `seq` is not exactly previous plus one.
- Hosts that serve user-controlled content on shared origins should not let tenants write under `/.well-known/` (the general RFC 8615 concern).

## Cover message (to the designated expert)

> I am requesting the permanent well-known URI suffix `openentity.json` for the Entity Document defined by the Open Entity Identity Standard, section 5.4. The specification is public, versioned and CC0-1.0, and the path has a working reference implementation. The resource is a signed JSON document that an AI system publishes at its domain so that a client can discover and verify the system's identifier. I am glad to adjust the template or the specification text to meet the expert's review.
