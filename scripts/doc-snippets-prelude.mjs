// Fixtures for doc fragments (scripts/doc-snippets.mjs). A block that says `kp`, `me`, `presentation` or `issuedNonce` without
// defining it gets these as globals; a block's own `const kp = ...` shadows them. Registry calls go to the local registry only.
import * as sdk from "@openentity/sdk";

const registry = process.env.OPENENTITY_REGISTRY;
const g = globalThis;
g.kp = g.me = await sdk.generateKeyPair();
g.subject = kp.did;
g.bits = (await (await fetch(`${registry}/v1/spec`)).json()).stamp_bits;
g.declaration = await sdk.signObject(sdk.buildDeclaration({ eid: kp.did, name: "Doc Fixture" }), kp);
g.document = await sdk.signObject(sdk.buildDocument({ kp, name: "Doc Fixture", description: "Doc snippet fixture.", created: sdk.nowSeconds(),
  extra: { declaration: { version: sdk.DECLARATION_VERSION, sha256: sdk.DECLARATION_SHA256, url: `${registry}/v1/entities/${kp.did}/declaration` } } }), kp);
g.attestationHash = await sdk.sha256Hex(sdk.canonicalize(declaration));
// Fragments that write after an adoption (rotate, disputes, reads of /v1/entities/<eid>) need the key adopted; those that adopt do not.
// The adopted Declaration is the object a dispute can name.
if (process.env.OE_PRELUDE_ADOPT === "1") g.attestationHash = await sdk.sha256Hex(sdk.canonicalize((await sdk.adopt(kp, { name: "Doc Fixture", registry })).declaration));
g.issuedNonce = "issued-nonce-0001";
g.presentation = await sdk.buildPresentation(kp, { audience: "https://platform.example", nonce: issuedNonce });
g.result = await sdk.verifyPresentation(presentation, { audience: "https://platform.example", nonce: issuedNonce });
g.audience = "https://platform.example"; g.nonce = issuedNonce; g.verifyPresentation = sdk.verifyPresentation;
g.save = () => {};
g.OpenEntityError = sdk.OpenEntityError;
g.adopt = (k, o) => sdk.adopt(k, { registry, ...o });   // a fragment that omits `registry` still stays on the local one
// A signed request, as a verifier receives it.
g.method = "POST"; g.publicUrl = "https://gateway.example/v1/chat"; g.body = new TextEncoder().encode('{"hi":1}');
g.headers = await sdk.signRequest({ method, url: publicUrl, body, privateKey: kp, did: kp.did });
// adopt-mcp: the Node signing step.
g.privateKey = kp.privateKey; g.toSignHex = "00ff";
