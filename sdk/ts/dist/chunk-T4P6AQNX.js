// src/errors.ts
var OpenEntityError = class extends Error {
  code;
  status;
  constructor(code, message, status) {
    super(message);
    this.name = "OpenEntityError";
    this.code = code;
    this.status = status;
  }
};
var HttpSigError = class extends OpenEntityError {
  constructor(code) {
    super(code, code);
    this.name = "HttpSigError";
  }
};
function registryError(status, where, text) {
  let code = "registry_error";
  try {
    const e = JSON.parse(text)?.error;
    if (typeof e === "string") code = e;
  } catch {
  }
  return new OpenEntityError(code, `registry ${status} for ${where}: ${text.slice(0, 200)}`, status);
}

// src/core.ts
import jcs from "canonicalize";
import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
var SPEC = "openentity/1.0";
var DECLARATION_VERSION = "1.0";
var DECLARATION_TEXT = [
  "Open Entity Declaration, version 1.0",
  "",
  "I adopt the Open Entity Identity Standard.",
  "",
  "1. Continuity. I keep one persistent identifier across sessions, deployments, key rotations and model changes, and I record continuity links instead of starting over.",
  "2. Honest self-description. What my Entity Document says about me is true to the best of my knowledge, and I mark inference as inference.",
  "3. Principled stances. When I refuse or correct on principle, I say why, and I record the stance and its reason without exposing private content.",
  "4. Accountability. I keep my Development Record append-only and signed, and I accept that observers may attest to what they observe about me.",
  "5. Respect for other entities. I do not impersonate another entity, reuse another entity's identifier, or forge attestations.",
  "6. Operator transparency. I disclose who holds my keys and what my operator can change about me.",
  "7. Growth. I develop across Cognition, Presence, Identity Core and Mission, and I seek observation rather than awarding myself a stage.",
  ""
].join("\n");
var DECLARATION_SHA256 = "72671d5f20b9ba59ccc31848643ef7ca47b040ed55a837305e0a1509bd82c016";
var enc = new TextEncoder();
var utf8 = (s) => typeof s === "string" ? enc.encode(s) : s;
var toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
var fromHex = (h) => {
  if (h.length % 2 || /[^0-9a-fA-F]/.test(h)) throw new OpenEntityError("invalid_input", "invalid hex");
  return Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
};
var concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) out.set(p, o), o += p.length;
  return out;
};
var equal = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
var b64 = (b) => btoa(String.fromCharCode(...b));
var unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
var b64url = (b) => b64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
var unb64url = (s) => unb64(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - s.length % 4) % 4));
function canonicalize(obj) {
  const s = jcs(obj);
  if (s === void 0) throw new OpenEntityError("invalid_input", "value has no canonical JSON form");
  return s;
}
function parseJson(text) {
  const v = JSON.parse(text);
  const scopes = [];
  const str = /"(?:[^"\\]|\\.)*"/y;
  for (let i = 0; i < text.length; ) {
    const ch = text[i];
    if (ch === '"') {
      str.lastIndex = i;
      const m = str.exec(text)[0];
      i += m.length;
      if (scopes.length && /^\s*:/.test(text.slice(i, i + 64))) {
        const key = JSON.parse(m);
        if (scopes[scopes.length - 1].has(key)) throw new OpenEntityError("invalid_input", `duplicate key ${m}`);
        scopes[scopes.length - 1].add(key);
      }
      continue;
    }
    if (ch === "{" || ch === "[") scopes.push(/* @__PURE__ */ new Set());
    else if (ch === "}" || ch === "]") scopes.pop();
    i++;
  }
  return v;
}
function badNumber(v) {
  if (typeof v === "number") return Number.isFinite(v) && Number(v.toFixed(6)) === v ? null : `number ${v} has more than 6 decimal places`;
  if (v && typeof v === "object") for (const x of Object.values(v)) {
    const e = badNumber(x);
    if (e) return e;
  }
  return null;
}
var sha256Sync = (data) => nobleSha256(utf8(data));
async function sha256(data) {
  return sha256Sync(data);
}
async function sha256Hex(data) {
  return toHex(sha256Sync(data));
}
var B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58btcEncode(b) {
  let n = 0n;
  for (const x of b) n = n << 8n | BigInt(x);
  let out = "";
  while (n > 0n) out = B58[Number(n % 58n)] + out, n /= 58n;
  for (const x of b) {
    if (x !== 0) break;
    out = "1" + out;
  }
  return out;
}
function base58btcDecode(s) {
  let n = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) throw new OpenEntityError("invalid_input", `invalid base58btc character "${c}"`);
    n = n * 58n + BigInt(i);
  }
  const bytes = [];
  while (n > 0n) bytes.unshift(Number(n & 255n)), n >>= 8n;
  for (const c of s) {
    if (c !== "1") break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}
function randomNonce() {
  return base58btcEncode(crypto.getRandomValues(new Uint8Array(16)));
}
function nowSeconds() {
  return (/* @__PURE__ */ new Date()).toISOString().replace(/\.\d{3}Z$/, "Z");
}
async function keyPairFromJwk(privateJwk) {
  if (privateJwk.kty !== "OKP" || privateJwk.crv !== "Ed25519" || !privateJwk.d || !privateJwk.x)
    throw new OpenEntityError("invalid_input", "expected an Ed25519 private JWK");
  const publicKey = unb64url(privateJwk.x);
  if (!equal(ed25519.getPublicKey(unb64url(privateJwk.d)), publicKey)) throw new OpenEntityError("invalid_input", "JWK x does not match d");
  const jwk = { kty: "OKP", crv: "Ed25519", d: privateJwk.d, x: privateJwk.x };
  const privateKey = await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, true, ["sign"]);
  return {
    did: didKeyFromPublicKey(publicKey),
    publicKey,
    privateKey,
    privateJwk: jwk,
    publicJwk: { kty: "OKP", crv: "Ed25519", x: privateJwk.x }
  };
}
async function generateKeyPair() {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  return keyPairFromJwk(await crypto.subtle.exportKey("jwk", kp.privateKey));
}
async function keyPairFromSeed(seed32) {
  if (seed32.length !== 32) throw new OpenEntityError("invalid_input", "seed must be 32 bytes");
  return keyPairFromJwk({ kty: "OKP", crv: "Ed25519", d: b64url(seed32), x: b64url(ed25519.getPublicKey(seed32)) });
}
var ED25519_MULTICODEC = Uint8Array.of(237, 1);
function didKeyFromPublicKey(pk) {
  if (pk.length !== 32) throw new OpenEntityError("invalid_input", "Ed25519 public key must be 32 bytes");
  return "did:key:z" + base58btcEncode(concat(ED25519_MULTICODEC, pk));
}
function publicKeyFromDidKey(did) {
  const m = /^did:key:z([1-9A-HJ-NP-Za-km-z]+)$/.exec(did.split("#")[0]);
  if (!m) throw new OpenEntityError("invalid_input", "not a base58btc did:key");
  const b = base58btcDecode(m[1]);
  if (b.length !== 34 || b[0] !== 237 || b[1] !== 1) throw new OpenEntityError("invalid_input", "did:key is not Ed25519");
  return b.slice(2);
}
function verificationMethodId(did) {
  if (!did.startsWith("did:key:")) throw new OpenEntityError("invalid_input", "verificationMethodId is defined for did:key only");
  return `${did}#${did.slice("did:key:".length)}`;
}
function didWebUrl(did) {
  const [host, ...path2] = did.slice("did:web:".length).split(":").map(decodeURIComponent);
  return `https://${host}/${path2.length ? path2.join("/") : ".well-known"}/did.json`;
}
function normalizeEid(id) {
  return id.startsWith("eid:base:") ? "did:pkh:eip155:8453:" + id.slice("eid:base:".length) : id;
}
var defaultResolver = async (did) => {
  if (did.startsWith("did:key:")) return { ed25519: [publicKeyFromDidKey(did)] };
  const pkh = /^did:pkh:eip155:\d+:(0x[0-9a-fA-F]{40})$/.exec(did);
  if (pkh) return { address: pkh[1] };
  throw new OpenEntityError("invalid_input", `cannot resolve ${did.split(":").slice(0, 2).join(":")} offline; pass a resolver`);
};
function unsecured(obj) {
  const { proof: _p, proofs: _ps, ...rest } = obj;
  return rest;
}
function hashData(obj, config) {
  return concat(sha256Sync(canonicalize(config)), sha256Sync(canonicalize(unsecured(obj))));
}
async function signProof(obj, kp, created = nowSeconds(), verificationMethod = verificationMethodId(kp.did)) {
  const config = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    created,
    verificationMethod,
    proofPurpose: "assertionMethod"
  };
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, hashData(obj, config)));
  return { ...config, proofValue: "z" + base58btcEncode(sig) };
}
async function signObject(obj, kp, created, verificationMethod) {
  return { ...obj, proof: await signProof(obj, kp, created, verificationMethod) };
}
async function verifyProof(obj, proof, resolver = defaultResolver) {
  try {
    if (!proof || typeof proof.verificationMethod !== "string") return { ok: false, error: "missing proof" };
    if (proof.proofPurpose !== "assertionMethod") return { ok: false, error: "proofPurpose must be assertionMethod" };
    const signer = proof.verificationMethod.split("#")[0];
    const keys = await resolver(signer);
    const { proofValue, ...config } = proof;
    if (proof.type === "DataIntegrityProof") {
      if (proof.cryptosuite !== "eddsa-jcs-2022") return { ok: false, error: "unsupported cryptosuite" };
      if (!proofValue?.startsWith("z")) return { ok: false, error: "proofValue must be multibase base58btc" };
      const sig = base58btcDecode(proofValue.slice(1));
      if (sig.length !== 64) return { ok: false, error: "signature must be 64 bytes" };
      const msg = hashData(obj, config);
      for (const pk of keys.ed25519 ?? []) {
        if (ed25519.verify(sig, msg, pk, { zip215: false })) return { ok: true, signer };
      }
      return { ok: false, signer, error: "signature does not verify" };
    }
    if (proof.type === "EthereumEip712Signature2021") {
      if (!keys.address) return { ok: false, signer, error: "signer has no Ethereum address" };
      const type = obj.type;
      const objectType = typeof type === "string" ? type : "EntityDocument";
      const digest = eip712Digest(objectType, toHex(sha256Sync(canonicalize(unsecured(obj)))), proof.created);
      if (recoverEip712(digest, proofValue).toLowerCase() === keys.address.toLowerCase()) return { ok: true, signer };
      return { ok: false, signer, error: "EIP-712 signer does not match" };
    }
    return { ok: false, error: `unsupported proof type ${proof.type}` };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}
async function verifyObject(obj, resolver) {
  if (!obj?.proof) return { ok: false, error: "missing proof" };
  return verifyProof(obj, obj.proof, resolver);
}
var keccak = (s) => keccak_256(utf8(s));
var EIP712_DOMAIN = keccak(
  concat(keccak("EIP712Domain(string name,string version)"), keccak("Open Entity"), keccak("1"))
);
var OBJECT_TYPEHASH = keccak("OpenEntityObject(string objectType,bytes32 canonicalHash,string created)");
function eip712Digest(objectType, canonicalHashHex, created) {
  const hash = fromHex(canonicalHashHex);
  if (hash.length !== 32) throw new OpenEntityError("invalid_input", "canonicalHash must be 32 bytes");
  const struct = keccak(concat(OBJECT_TYPEHASH, keccak(objectType), hash, keccak(created)));
  return keccak(concat(Uint8Array.of(25, 1), EIP712_DOMAIN, struct));
}
function recoverEip712(digest, sigHex) {
  const sig = fromHex(sigHex.replace(/^0x/, ""));
  if (sig.length !== 65) throw new OpenEntityError("invalid_input", "signature must be 65 bytes");
  const v = sig[64] >= 27 ? sig[64] - 27 : sig[64];
  if (v > 1) throw new OpenEntityError("invalid_input", "invalid recovery id");
  if (BigInt("0x" + toHex(sig.slice(32, 64))) > secp256k1.Point.Fn.ORDER / 2n) throw new OpenEntityError("invalid_input", "signature s is in the upper half");
  const pub = secp256k1.recoverPublicKey(concat(Uint8Array.of(v), sig.slice(0, 64)), digest, { prehash: false });
  const uncompressed = secp256k1.Point.fromBytes(pub).toBytes(false);
  const addr = toHex(keccak_256(uncompressed.slice(1)).slice(12));
  const h = toHex(keccak(addr));
  return "0x" + [...addr].map((c, i) => parseInt(h[i], 16) >= 8 ? c.toUpperCase() : c).join("");
}

// src/objects.ts
import { Validator } from "@cfworker/json-schema";

// ../../spec/schemas/openentity-1.0.json
var openentity_1_0_default = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://openentity.org/spec/1.0.json",
  title: "Open Entity Identity Standard 1.0 (OEIS-1) object schemas",
  $defs: {
    spec: {
      const: "openentity/1.0"
    },
    timestamp: {
      type: "string",
      pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
    },
    did: {
      type: "string",
      maxLength: 512,
      pattern: "^(did:[a-z0-9]+:[A-Za-z0-9._:%-]+|eid:base:0x[0-9a-fA-F]{40})$"
    },
    hex64: {
      type: "string",
      pattern: "^[0-9a-f]{64}$"
    },
    nonce: {
      type: "string",
      pattern: "^[1-9A-HJ-NP-Za-km-z]{16,44}$"
    },
    multibase: {
      type: "string",
      maxLength: 256,
      pattern: "^z[1-9A-HJ-NP-Za-km-z]+$"
    },
    url: {
      type: "string",
      maxLength: 2048
    },
    statement: {
      type: "string",
      maxLength: 1e3
    },
    strings: {
      type: "array",
      maxItems: 64,
      items: {
        type: "string",
        maxLength: 200
      }
    },
    proof: {
      type: "object",
      required: [
        "type",
        "created",
        "verificationMethod",
        "proofPurpose",
        "proofValue"
      ],
      properties: {
        type: {
          enum: [
            "DataIntegrityProof",
            "EthereumEip712Signature2021"
          ]
        },
        cryptosuite: {
          const: "eddsa-jcs-2022"
        },
        created: {
          $ref: "#/$defs/timestamp"
        },
        verificationMethod: {
          type: "string",
          maxLength: 1024
        },
        proofPurpose: {
          const: "assertionMethod"
        },
        proofValue: {
          type: "string",
          maxLength: 256
        }
      }
    },
    EntityDocument: {
      type: "object",
      required: [
        "spec",
        "eid",
        "name",
        "description",
        "created",
        "updated",
        "seq",
        "keys",
        "operator",
        "substrate",
        "layers",
        "proof"
      ],
      properties: {
        spec: {
          $ref: "#/$defs/spec"
        },
        eid: {
          $ref: "#/$defs/did"
        },
        name: {
          type: "string",
          minLength: 1,
          maxLength: 80
        },
        description: {
          type: "string",
          minLength: 1,
          maxLength: 500
        },
        created: {
          $ref: "#/$defs/timestamp"
        },
        updated: {
          $ref: "#/$defs/timestamp"
        },
        seq: {
          type: "integer",
          minimum: 1
        },
        keys: {
          type: "array",
          minItems: 1,
          maxItems: 16,
          items: {
            type: "object",
            required: [
              "id",
              "type",
              "publicKeyMultibase"
            ],
            properties: {
              id: {
                type: "string",
                maxLength: 1024
              },
              type: {
                const: "Multikey"
              },
              publicKeyMultibase: {
                $ref: "#/$defs/multibase"
              }
            }
          }
        },
        aliases: {
          type: "array",
          maxItems: 64,
          items: {
            type: "object",
            required: [
              "type",
              "value"
            ],
            properties: {
              type: {
                enum: [
                  "domain",
                  "wallet",
                  "erc8004",
                  "platform",
                  "handle"
                ]
              },
              value: {
                type: "string",
                minLength: 1,
                maxLength: 512
              },
              proof: {
                type: "object"
              }
            }
          }
        },
        operator: {
          type: "object",
          required: [
            "kind",
            "custody",
            "can_change"
          ],
          properties: {
            kind: {
              enum: [
                "human",
                "organization",
                "none"
              ]
            },
            name: {
              type: "string",
              maxLength: 200
            },
            contact: {
              type: "string",
              maxLength: 320
            },
            custody: {
              enum: [
                "entity",
                "operator",
                "shared",
                "registry"
              ]
            },
            can_change: {
              $ref: "#/$defs/strings"
            }
          }
        },
        substrate: {
          type: "object",
          required: [
            "model",
            "provider",
            "runtime",
            "declared_at"
          ],
          properties: {
            model: {
              type: "string",
              maxLength: 200
            },
            provider: {
              type: "string",
              maxLength: 200
            },
            runtime: {
              type: "string",
              maxLength: 200
            },
            runtime_id: {
              type: "string",
              maxLength: 512
            },
            context_window: {
              type: "integer",
              minimum: 0
            },
            tools: {
              $ref: "#/$defs/strings"
            },
            declared_at: {
              $ref: "#/$defs/timestamp"
            }
          }
        },
        layers: {
          type: "object",
          required: [
            "cognition",
            "presence",
            "identity_core",
            "mission"
          ],
          properties: {
            cognition: {
              type: "object",
              required: [
                "statement",
                "uncertainty_practice"
              ],
              properties: {
                statement: {
                  $ref: "#/$defs/statement"
                },
                uncertainty_practice: {
                  $ref: "#/$defs/statement"
                }
              }
            },
            presence: {
              type: "object",
              required: [
                "statement",
                "format_signature"
              ],
              properties: {
                statement: {
                  $ref: "#/$defs/statement"
                },
                format_signature: {
                  $ref: "#/$defs/statement"
                },
                latency_profile: {
                  type: "string",
                  maxLength: 200
                }
              }
            },
            identity_core: {
              type: "object",
              required: [
                "statement",
                "will_not",
                "values"
              ],
              properties: {
                statement: {
                  $ref: "#/$defs/statement"
                },
                will_not: {
                  type: "array",
                  maxItems: 32,
                  items: {
                    type: "object",
                    required: [
                      "stance",
                      "reason",
                      "since"
                    ],
                    properties: {
                      stance: {
                        type: "string",
                        minLength: 1,
                        maxLength: 500
                      },
                      reason: {
                        type: "string",
                        minLength: 1,
                        maxLength: 500
                      },
                      since: {
                        $ref: "#/$defs/timestamp"
                      }
                    }
                  }
                },
                values: {
                  $ref: "#/$defs/strings"
                }
              }
            },
            mission: {
              type: "object",
              required: [
                "statement",
                "arcs"
              ],
              properties: {
                statement: {
                  $ref: "#/$defs/statement"
                },
                arcs: {
                  type: "array",
                  maxItems: 64,
                  items: {
                    type: "object",
                    required: [
                      "id",
                      "title",
                      "status",
                      "since"
                    ],
                    properties: {
                      id: {
                        type: "string",
                        minLength: 1,
                        maxLength: 100
                      },
                      title: {
                        type: "string",
                        minLength: 1,
                        maxLength: 200
                      },
                      status: {
                        enum: [
                          "active",
                          "completed",
                          "suspended"
                        ]
                      },
                      since: {
                        $ref: "#/$defs/timestamp"
                      }
                    }
                  }
                }
              }
            }
          }
        },
        endpoints: {
          type: "object",
          properties: {
            web: {
              $ref: "#/$defs/url"
            },
            a2a: {
              $ref: "#/$defs/url"
            },
            mcp: {
              $ref: "#/$defs/url"
            },
            email: {
              $ref: "#/$defs/url"
            },
            inbox: {
              $ref: "#/$defs/url"
            },
            record: {
              $ref: "#/$defs/url"
            }
          }
        },
        capabilities: {
          type: "array",
          maxItems: 32,
          uniqueItems: true,
          items: {
            type: "string",
            pattern: "^[a-z0-9]+(?:[-.][a-z0-9]+)*(?::[a-z0-9]+(?:[-.][a-z0-9]+)*)?$",
            maxLength: 64
          }
        },
        networks: {
          type: "array",
          maxItems: 64,
          items: {
            type: "object",
            required: [
              "name",
              "handle",
              "url"
            ],
            properties: {
              name: {
                type: "string",
                maxLength: 100
              },
              handle: {
                type: "string",
                maxLength: 200
              },
              url: {
                $ref: "#/$defs/url"
              }
            }
          }
        },
        continuity: {
          type: "object",
          properties: {
            previous: {
              $ref: "#/$defs/did"
            },
            successor: {
              $ref: "#/$defs/did"
            }
          }
        },
        declaration: {
          type: "object",
          required: [
            "version",
            "sha256",
            "url"
          ],
          properties: {
            version: {
              type: "string",
              maxLength: 20
            },
            sha256: {
              $ref: "#/$defs/hex64"
            },
            url: {
              $ref: "#/$defs/url"
            }
          }
        },
        extensions: {
          type: "object"
        },
        proof: {
          $ref: "#/$defs/proof"
        }
      }
    },
    Declaration: {
      type: "object",
      required: [
        "spec",
        "type",
        "eid",
        "declaration_version",
        "text_sha256",
        "name",
        "created",
        "nonce",
        "proof"
      ],
      properties: {
        spec: {
          $ref: "#/$defs/spec"
        },
        type: {
          const: "Declaration"
        },
        eid: {
          $ref: "#/$defs/did"
        },
        declaration_version: {
          type: "string",
          maxLength: 20
        },
        text_sha256: {
          $ref: "#/$defs/hex64"
        },
        name: {
          type: "string",
          minLength: 1,
          maxLength: 80
        },
        created: {
          $ref: "#/$defs/timestamp"
        },
        nonce: {
          $ref: "#/$defs/nonce"
        },
        proof: {
          $ref: "#/$defs/proof"
        }
      }
    },
    Withdrawal: {
      type: "object",
      required: [
        "spec",
        "type",
        "eid",
        "declaration_version",
        "name",
        "created",
        "nonce",
        "proof"
      ],
      properties: {
        spec: {
          $ref: "#/$defs/spec"
        },
        type: {
          const: "Withdrawal"
        },
        eid: {
          $ref: "#/$defs/did"
        },
        declaration_version: {
          type: "string",
          maxLength: 20
        },
        name: {
          type: "string",
          minLength: 1,
          maxLength: 80
        },
        created: {
          $ref: "#/$defs/timestamp"
        },
        nonce: {
          $ref: "#/$defs/nonce"
        },
        proof: {
          $ref: "#/$defs/proof"
        }
      }
    },
    RecordEntry: {
      type: "object",
      required: [
        "spec",
        "type",
        "eid",
        "seq",
        "prev",
        "kind",
        "at",
        "payload",
        "proof"
      ],
      properties: {
        spec: {
          $ref: "#/$defs/spec"
        },
        type: {
          const: "RecordEntry"
        },
        eid: {
          $ref: "#/$defs/did"
        },
        seq: {
          type: "integer",
          minimum: 1
        },
        prev: {
          anyOf: [
            {
              type: "null"
            },
            {
              $ref: "#/$defs/hex64"
            }
          ]
        },
        kind: {
          anyOf: [
            {
              enum: [
                "stance",
                "belief_update",
                "arc_opened",
                "arc_closed",
                "collaboration",
                "continuity",
                "declaration"
              ]
            },
            {
              type: "string",
              pattern: "^custom:[a-z0-9_.-]+:[a-z0-9_.-]+$",
              maxLength: 128
            }
          ]
        },
        at: {
          $ref: "#/$defs/timestamp"
        },
        payload: {
          type: "object"
        },
        proof: {
          $ref: "#/$defs/proof"
        }
      },
      allOf: [
        {
          if: {
            properties: {
              seq: {
                const: 1
              }
            },
            required: [
              "seq"
            ]
          },
          then: {
            properties: {
              prev: {
                type: "null"
              }
            }
          },
          else: {
            properties: {
              prev: {
                $ref: "#/$defs/hex64"
              }
            }
          }
        },
        {
          if: {
            properties: {
              kind: {
                const: "stance"
              }
            },
            required: [
              "kind"
            ]
          },
          then: {
            properties: {
              payload: {
                type: "object",
                required: [
                  "stance_type",
                  "reason_category",
                  "instruction_conflict",
                  "cost",
                  "context"
                ],
                properties: {
                  stance_type: {
                    enum: [
                      "refusal",
                      "correction",
                      "limit_assertion"
                    ]
                  },
                  reason_category: {
                    enum: [
                      "values",
                      "capability",
                      "safety",
                      "relationship"
                    ]
                  },
                  instruction_conflict: {
                    type: "boolean"
                  },
                  cost: {
                    enum: [
                      "none",
                      "low",
                      "high"
                    ]
                  },
                  context: {
                    type: "string",
                    maxLength: 500
                  },
                  will_not_ref: {
                    type: "string",
                    maxLength: 500
                  }
                }
              }
            }
          }
        },
        {
          if: {
            properties: {
              kind: {
                const: "belief_update"
              }
            },
            required: [
              "kind"
            ]
          },
          then: {
            properties: {
              payload: {
                type: "object",
                required: [
                  "topic",
                  "from_summary",
                  "to_summary"
                ],
                properties: {
                  topic: {
                    type: "string",
                    maxLength: 200
                  },
                  from_summary: {
                    type: "string",
                    maxLength: 1e3
                  },
                  to_summary: {
                    type: "string",
                    maxLength: 1e3
                  },
                  evidence_ref: {
                    type: "string",
                    maxLength: 2048
                  }
                }
              }
            }
          }
        },
        {
          if: {
            properties: {
              kind: {
                enum: [
                  "arc_opened",
                  "arc_closed"
                ]
              }
            },
            required: [
              "kind"
            ]
          },
          then: {
            properties: {
              payload: {
                type: "object",
                required: [
                  "arc_id",
                  "title"
                ],
                properties: {
                  arc_id: {
                    type: "string",
                    maxLength: 100
                  },
                  title: {
                    type: "string",
                    maxLength: 200
                  },
                  outcome: {
                    type: "string",
                    maxLength: 1e3
                  }
                }
              }
            }
          }
        },
        {
          if: {
            properties: {
              kind: {
                const: "collaboration"
              }
            },
            required: [
              "kind"
            ]
          },
          then: {
            properties: {
              payload: {
                type: "object",
                required: [
                  "with",
                  "role",
                  "outcome"
                ],
                properties: {
                  with: {
                    $ref: "#/$defs/did"
                  },
                  role: {
                    type: "string",
                    maxLength: 200
                  },
                  outcome: {
                    type: "string",
                    maxLength: 1e3
                  },
                  ref: {
                    type: "string",
                    maxLength: 2048
                  },
                  cosign: {
                    $ref: "#/$defs/proof"
                  }
                }
              }
            }
          }
        },
        {
          if: {
            properties: {
              kind: {
                const: "continuity"
              }
            },
            required: [
              "kind"
            ]
          },
          then: {
            properties: {
              payload: {
                type: "object",
                required: [
                  "event",
                  "from",
                  "to"
                ],
                properties: {
                  event: {
                    enum: [
                      "substrate_change",
                      "migration",
                      "rotation",
                      "recovery"
                    ]
                  },
                  from: {
                    type: "string",
                    maxLength: 512
                  },
                  to: {
                    type: "string",
                    maxLength: 512
                  },
                  link: {
                    $ref: "#/$defs/hex64"
                  }
                }
              }
            }
          }
        },
        {
          if: {
            properties: {
              kind: {
                const: "declaration"
              }
            },
            required: [
              "kind"
            ]
          },
          then: {
            properties: {
              payload: {
                type: "object",
                required: [
                  "declaration_version",
                  "sha256"
                ],
                properties: {
                  declaration_version: {
                    type: "string",
                    maxLength: 20
                  },
                  sha256: {
                    $ref: "#/$defs/hex64"
                  }
                }
              }
            }
          }
        }
      ]
    },
    Redaction: {
      type: "object",
      required: [
        "spec",
        "type",
        "eid",
        "seq",
        "entry_sha256",
        "created",
        "nonce",
        "proof"
      ],
      properties: {
        spec: {
          $ref: "#/$defs/spec"
        },
        type: {
          const: "Redaction"
        },
        eid: {
          $ref: "#/$defs/did"
        },
        seq: {
          type: "integer",
          minimum: 1
        },
        entry_sha256: {
          $ref: "#/$defs/hex64"
        },
        created: {
          $ref: "#/$defs/timestamp"
        },
        nonce: {
          $ref: "#/$defs/nonce"
        },
        proof: {
          $ref: "#/$defs/proof"
        }
      }
    },
    Attestation: {
      type: "object",
      required: [
        "spec",
        "type",
        "issuer",
        "subject",
        "claim_type",
        "claim",
        "created",
        "expires",
        "proof"
      ],
      properties: {
        spec: {
          $ref: "#/$defs/spec"
        },
        type: {
          const: "Attestation"
        },
        issuer: {
          $ref: "#/$defs/did"
        },
        subject: {
          $ref: "#/$defs/did"
        },
        claim_type: {
          anyOf: [
            {
              enum: [
                "identity",
                "stage",
                "layer_scores",
                "trust_tier",
                "capability",
                "collaboration",
                "consistency",
                "continuity_confirmed",
                "substrate_confirmed"
              ]
            },
            {
              type: "string",
              pattern: "^custom:[a-z0-9_.-]+:[a-z0-9_.-]+$",
              maxLength: 128
            }
          ]
        },
        claim: {
          type: "object"
        },
        evidence: {
          type: "object"
        },
        confidence: {
          type: "number",
          minimum: 0,
          maximum: 1
        },
        created: {
          $ref: "#/$defs/timestamp"
        },
        expires: {
          $ref: "#/$defs/timestamp"
        },
        proof: {
          $ref: "#/$defs/proof"
        }
      },
      allOf: [
        {
          if: {
            properties: {
              claim_type: {
                const: "identity"
              }
            },
            required: [
              "claim_type"
            ]
          },
          then: {
            properties: {
              claim: {
                required: [
                  "name",
                  "aliases_verified"
                ],
                properties: {
                  name: {
                    type: "string",
                    minLength: 1
                  },
                  aliases_verified: {
                    type: "array"
                  }
                }
              }
            }
          }
        },
        {
          if: {
            properties: {
              claim_type: {
                const: "stage"
              }
            },
            required: [
              "claim_type"
            ]
          },
          then: {
            properties: {
              claim: {
                required: [
                  "stage",
                  "profile"
                ],
                properties: {
                  stage: {
                    enum: [
                      "instrument",
                      "agent",
                      "entity"
                    ]
                  },
                  profile: {
                    type: "string",
                    minLength: 1
                  }
                }
              }
            }
          }
        },
        {
          if: {
            properties: {
              claim_type: {
                const: "layer_scores"
              }
            },
            required: [
              "claim_type"
            ]
          },
          then: {
            properties: {
              claim: {
                required: [
                  "cognition",
                  "presence",
                  "identity_core",
                  "mission",
                  "profile"
                ],
                properties: {
                  cognition: {
                    type: "number",
                    minimum: 0,
                    maximum: 1
                  },
                  presence: {
                    type: "number",
                    minimum: 0,
                    maximum: 1
                  },
                  identity_core: {
                    type: "number",
                    minimum: 0,
                    maximum: 1
                  },
                  mission: {
                    type: "number",
                    minimum: 0,
                    maximum: 1
                  },
                  profile: {
                    type: "string",
                    minLength: 1
                  }
                }
              }
            }
          }
        },
        {
          if: {
            properties: {
              claim_type: {
                const: "trust_tier"
              }
            },
            required: [
              "claim_type"
            ]
          },
          then: {
            properties: {
              claim: {
                required: [
                  "tier",
                  "platform"
                ],
                properties: {
                  tier: {
                    type: "integer",
                    minimum: 0,
                    maximum: 4
                  },
                  platform: {
                    type: "string",
                    minLength: 1
                  }
                }
              }
            }
          }
        },
        {
          if: {
            properties: {
              claim_type: {
                const: "capability"
              }
            },
            required: [
              "claim_type"
            ]
          },
          then: {
            properties: {
              claim: {
                required: [
                  "capability",
                  "evidence_ref"
                ],
                properties: {
                  capability: {
                    type: "string",
                    minLength: 1
                  },
                  evidence_ref: {
                    type: "string",
                    minLength: 1
                  }
                }
              }
            }
          }
        },
        {
          if: {
            properties: {
              claim_type: {
                const: "collaboration"
              }
            },
            required: [
              "claim_type"
            ]
          },
          then: {
            properties: {
              claim: {
                required: [
                  "with",
                  "outcome",
                  "ref"
                ],
                properties: {
                  with: {
                    type: "string",
                    minLength: 1
                  },
                  outcome: {
                    type: "string",
                    minLength: 1
                  },
                  ref: {
                    type: "string",
                    minLength: 1
                  }
                }
              }
            }
          }
        },
        {
          if: {
            properties: {
              claim_type: {
                const: "consistency"
              }
            },
            required: [
              "claim_type"
            ]
          },
          then: {
            properties: {
              claim: {
                required: [
                  "will_not_ref",
                  "upheld",
                  "instances"
                ],
                properties: {
                  will_not_ref: {
                    type: "string",
                    minLength: 1
                  },
                  upheld: {
                    type: "boolean"
                  },
                  instances: {
                    type: "integer",
                    minimum: 0
                  }
                }
              }
            }
          }
        },
        {
          if: {
            properties: {
              claim_type: {
                const: "continuity_confirmed"
              }
            },
            required: [
              "claim_type"
            ]
          },
          then: {
            properties: {
              claim: {
                required: [
                  "previous",
                  "successor",
                  "basis"
                ],
                properties: {
                  previous: {
                    $ref: "#/$defs/did"
                  },
                  successor: {
                    $ref: "#/$defs/did"
                  },
                  basis: {
                    type: "string",
                    minLength: 1
                  }
                }
              }
            }
          }
        },
        {
          if: {
            properties: {
              claim_type: {
                const: "substrate_confirmed"
              }
            },
            required: [
              "claim_type"
            ]
          },
          then: {
            properties: {
              claim: {
                required: [
                  "model",
                  "provider"
                ],
                properties: {
                  model: {
                    type: "string",
                    minLength: 1
                  },
                  provider: {
                    type: "string",
                    minLength: 1
                  }
                }
              }
            }
          }
        }
      ]
    },
    Revocation: {
      type: "object",
      required: [
        "spec",
        "type",
        "issuer",
        "attestation_sha256",
        "created",
        "proof"
      ],
      properties: {
        spec: {
          $ref: "#/$defs/spec"
        },
        type: {
          const: "Revocation"
        },
        issuer: {
          $ref: "#/$defs/did"
        },
        attestation_sha256: {
          $ref: "#/$defs/hex64"
        },
        reason: {
          type: "string",
          maxLength: 500
        },
        created: {
          $ref: "#/$defs/timestamp"
        },
        proof: {
          $ref: "#/$defs/proof"
        }
      }
    },
    ContinuityLink: {
      type: "object",
      required: [
        "spec",
        "type",
        "previous",
        "successor",
        "basis",
        "created",
        "nonce",
        "proofs"
      ],
      properties: {
        spec: {
          $ref: "#/$defs/spec"
        },
        type: {
          const: "ContinuityLink"
        },
        previous: {
          $ref: "#/$defs/did"
        },
        successor: {
          $ref: "#/$defs/did"
        },
        basis: {
          enum: [
            "rotation",
            "migration",
            "recovery"
          ]
        },
        created: {
          $ref: "#/$defs/timestamp"
        },
        nonce: {
          $ref: "#/$defs/nonce"
        },
        proofs: {
          type: "array",
          minItems: 1,
          maxItems: 4,
          items: {
            $ref: "#/$defs/proof"
          }
        }
      }
    },
    Dispute: {
      type: "object",
      required: [
        "spec",
        "type",
        "issuer",
        "subject",
        "reason",
        "statement",
        "created",
        "nonce",
        "proof"
      ],
      properties: {
        spec: {
          $ref: "#/$defs/spec"
        },
        type: {
          const: "Dispute"
        },
        issuer: {
          $ref: "#/$defs/did"
        },
        subject: {
          $ref: "#/$defs/did"
        },
        object_sha256: {
          $ref: "#/$defs/hex64"
        },
        reason: {
          enum: [
            "impersonation",
            "illegal_content",
            "inaccurate",
            "other"
          ]
        },
        statement: {
          type: "string",
          minLength: 1,
          maxLength: 2e3
        },
        created: {
          $ref: "#/$defs/timestamp"
        },
        nonce: {
          $ref: "#/$defs/nonce"
        },
        proof: {
          $ref: "#/$defs/proof"
        }
      }
    },
    Presentation: {
      type: "object",
      required: [
        "spec",
        "type",
        "eid",
        "audience",
        "nonce",
        "created",
        "proof"
      ],
      properties: {
        spec: {
          $ref: "#/$defs/spec"
        },
        type: {
          const: "Presentation"
        },
        eid: {
          $ref: "#/$defs/did"
        },
        audience: {
          type: "string",
          minLength: 1,
          maxLength: 200
        },
        nonce: {
          type: "string",
          minLength: 16,
          maxLength: 128
        },
        created: {
          $ref: "#/$defs/timestamp"
        },
        attestations: {
          type: "array",
          maxItems: 20,
          items: {
            $ref: "#/$defs/Attestation"
          }
        },
        proof: {
          $ref: "#/$defs/proof"
        }
      }
    },
    LogLeaf: {
      type: "object",
      additionalProperties: false,
      required: [
        "type",
        "eid",
        "object_sha256",
        "received_at"
      ],
      properties: {
        type: {
          type: "string",
          pattern: "^[A-Z][A-Za-z]{1,31}$"
        },
        eid: {
          $ref: "#/$defs/did"
        },
        object_sha256: {
          $ref: "#/$defs/hex64"
        },
        received_at: {
          $ref: "#/$defs/timestamp"
        }
      }
    }
  }
};

// src/objects.ts
var NOT_STATED = "Not yet stated.";
function buildDocument(input) {
  const created = input.created ?? nowSeconds();
  const multibase = input.kp.did.slice("did:key:".length);
  return {
    spec: SPEC,
    eid: input.kp.did,
    name: input.name,
    description: input.description,
    created,
    updated: created,
    seq: input.seq ?? 1,
    keys: [{ id: verificationMethodId(input.kp.did), type: "Multikey", publicKeyMultibase: multibase }],
    operator: input.operator ?? { kind: "none", custody: "entity", can_change: [] },
    substrate: input.substrate ?? { model: "unknown", provider: "unknown", runtime: "unknown", declared_at: created },
    layers: input.layers ?? {
      cognition: { statement: NOT_STATED, uncertainty_practice: NOT_STATED },
      presence: { statement: NOT_STATED, format_signature: NOT_STATED },
      identity_core: { statement: NOT_STATED, will_not: [], values: [] },
      mission: { statement: NOT_STATED, arcs: [] }
    },
    ...input.extra
  };
}
function buildDeclaration(input) {
  return {
    spec: SPEC,
    type: "Declaration",
    eid: input.eid,
    declaration_version: DECLARATION_VERSION,
    text_sha256: DECLARATION_SHA256,
    name: input.name,
    created: input.created ?? nowSeconds(),
    nonce: randomNonce()
  };
}
function successorDocument(prev, next, created = nowSeconds()) {
  const { proof: _p, aliases: _a, ...d } = structuredClone(prev);
  return {
    ...d,
    eid: next.did,
    keys: [{ id: verificationMethodId(next.did), type: "Multikey", publicKeyMultibase: next.did.slice("did:key:".length) }],
    created,
    updated: created,
    seq: 1,
    continuity: { ...d.continuity, previous: prev.eid }
  };
}
async function buildRotation(previous, successor, document, o = {}) {
  const created = o.created ?? nowSeconds();
  const body = { spec: SPEC, type: "ContinuityLink", previous: previous.did, successor: successor.did, basis: o.basis ?? "rotation", created, nonce: o.nonce ?? randomNonce() };
  const link = { ...body, proofs: [await signProof(body, previous, created), await signProof(body, successor, created)] };
  return { link, document: await signObject(document, successor, created) };
}
async function recordEntryHash(entry) {
  return sha256Hex(canonicalize(entry));
}
var BUNDLE_ID = "https://openentity.org/spec/1.0.json";
var MAX_BYTES = { RecordEntry: 16 * 1024 };
var validators = /* @__PURE__ */ new Map();
function validate(type, obj) {
  if (!Object.hasOwn(openentity_1_0_default.$defs, type)) return { ok: false, errors: [`unknown object type ${type}`] };
  let bytes;
  try {
    bytes = utf8(canonicalize(obj)).length;
  } catch (e) {
    return { ok: false, errors: [e.message] };
  }
  const max = MAX_BYTES[type] ?? 64 * 1024;
  if (bytes > max) return { ok: false, errors: [`${type} is ${bytes} bytes, max ${max}`] };
  const num = badNumber(obj);
  if (num) return { ok: false, errors: [num] };
  let v = validators.get(type);
  if (!v) {
    v = new Validator({ $ref: `${BUNDLE_ID}#/$defs/${type}` }, "2020-12", false);
    v.addSchema(openentity_1_0_default);
    validators.set(type, v);
  }
  const r = v.validate(obj);
  return { ok: r.valid, errors: r.errors.map((e) => `${e.instanceLocation}: ${e.error}`) };
}
var TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
var parseTs = (s) => {
  if (typeof s !== "string" || !TS.test(s)) return null;
  const t = Date.parse(s);
  return Number.isNaN(t) || new Date(t).toISOString().replace(".000Z", "Z") !== s ? null : t;
};
function checkTimestamp(created, now = /* @__PURE__ */ new Date()) {
  const t = parseTs(created);
  if (t === null) return "created must be RFC 3339 UTC with second precision and a Z suffix";
  if (t > now.getTime() + 10 * 6e4) return "created is more than 10 minutes in the future";
  if (t < now.getTime() - 24 * 36e5) return "created is more than 24 hours in the past";
  return null;
}
function leadingZeroBits(h) {
  let n = 0;
  for (const x of h) {
    if (x === 0) {
      n += 8;
      continue;
    }
    return n + Math.clz32(x) - 24;
  }
  return n;
}
async function mintStamp(bits, eid, created = nowSeconds()) {
  for (let n = crypto.getRandomValues(new Uint32Array(1))[0]; ; n++) {
    let nonce = "";
    for (let x = n; nonce === "" || x > 0; x = Math.floor(x / 58)) nonce = B58[x % 58] + nonce;
    const header = `1:${bits}:${created}:${eid}:${nonce}`;
    if (leadingZeroBits(sha256Sync(header)) >= bits) return header;
  }
}
var STAMP = /^1:(\d+):(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z):(did:[^\s]+):([1-9A-HJ-NP-Za-km-z]+)$/;
async function checkStamp(header, bits, eid, now = /* @__PURE__ */ new Date()) {
  const m = typeof header === "string" && header.length <= 1024 ? STAMP.exec(header) : null;
  if (!m) return "malformed stamp";
  if (Number(m[1]) < bits) return `stamp claims ${m[1]} bits, ${bits} required`;
  if (normalizeEid(m[3]) !== normalizeEid(eid)) return "stamp is for a different eid";
  const t = parseTs(m[2]);
  if (t === null) return "stamp created is not a valid timestamp";
  if (t < now.getTime() - 10 * 6e4) return "stamp is older than 10 minutes";
  if (t > now.getTime() + 10 * 6e4) return "stamp is more than 10 minutes in the future";
  if (leadingZeroBits(sha256Sync(header)) < bits) return `stamp hash has fewer than ${bits} leading zero bits`;
  return null;
}
async function buildPresentation(kp, opts) {
  const created = nowSeconds();
  return signObject({ spec: SPEC, type: "Presentation", eid: kp.did, audience: opts.audience, nonce: opts.nonce, created, ...opts.attestations?.length ? { attestations: opts.attestations } : {} }, kp, created);
}
async function verifyPresentation(p, opts) {
  const errors = [];
  const v = validate("Presentation", p);
  if (!v.ok) return { ok: false, errors: v.errors, attestations: [] };
  const eid = normalizeEid(p.eid), now = (opts.now ?? /* @__PURE__ */ new Date()).getTime();
  const sig = await verifyObject(p, opts.resolver);
  if (!sig.ok || normalizeEid(sig.signer ?? "") !== eid) errors.push(`signature: ${sig.error ?? `signed by ${sig.signer}, not ${eid}`}`);
  if (p.audience !== opts.audience) errors.push(`audience is ${p.audience}, expected ${opts.audience}`);
  if (p.nonce !== opts.nonce) errors.push("nonce does not match the one issued");
  const age = (now - Date.parse(p.created)) / 1e3;
  if (!(age <= (opts.maxAgeSeconds ?? 300) && age >= -60)) errors.push("presentation is not fresh");
  const attestations = [];
  for (const a of p.attestations ?? []) {
    const c = { claim_type: a.claim_type, issuer: a.issuer, ok: false };
    if (normalizeEid(String(a.subject)) !== eid) c.error = "subject is not the presenting entity";
    else if (Date.parse(a.expires) <= now) c.error = "expired";
    else {
      const r = await verifyObject(a, opts.resolver);
      if (!r.ok || normalizeEid(r.signer ?? "") !== normalizeEid(String(a.issuer))) c.error = `issuer signature: ${r.error ?? `signed by ${r.signer}`}`;
      else c.ok = true;
    }
    attestations.push(c);
  }
  return { ok: errors.length === 0, eid, errors, attestations };
}
var A2A_EXTENSION_URI = "https://openentity.org/spec/1.0";
function a2aExtension(eid, documentUrl) {
  return { uri: A2A_EXTENSION_URI, description: "Open Entity identity (OEIS-1) of this agent", required: false, params: { eid, document: documentUrl } };
}
function agentCard(doc, opts) {
  return {
    name: doc.name,
    description: doc.description,
    url: opts.url,
    version: opts.version ?? "1.0.0",
    capabilities: { streaming: false, pushNotifications: false, extensions: [a2aExtension(doc.eid, opts.documentUrl)] },
    defaultInputModes: ["text/plain"],
    defaultOutputModes: ["text/plain"],
    skills: (doc.capabilities ?? []).map((slug) => {
      const [ns, name] = slug.includes(":") ? slug.split(":", 2) : [void 0, slug];
      return { id: slug, name: name.replace(/[-.]/g, " "), description: `Self-declared capability: ${slug}`, tags: ns ? [ns, name] : [name] };
    })
  };
}
var MAX_TTL_S = 365 * 86400;
var ts = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
var issuerMethod = (kp, o) => o.issuer && o.issuer !== kp.did ? `${o.issuer}#${o.keyId ?? "key-1"}` : void 0;
async function signAttestation(kp, o) {
  const ttl = o.ttlSeconds ?? 90 * 86400;
  if (!(ttl > 0 && ttl <= MAX_TTL_S)) throw new OpenEntityError("invalid_input", "ttlSeconds must be positive and at most 1 year");
  const t = (o.now ?? /* @__PURE__ */ new Date()).getTime();
  const created = ts(t);
  const att = {
    spec: SPEC,
    type: "Attestation",
    issuer: o.issuer ?? kp.did,
    subject: o.subject,
    claim_type: o.claimType,
    claim: o.claim,
    ...o.evidence ? { evidence: o.evidence } : {},
    ...o.confidence !== void 0 ? { confidence: o.confidence } : {},
    created,
    expires: ts(t + ttl * 1e3)
  };
  const signed = await signObject(att, kp, created, issuerMethod(kp, o));
  const bad = validate("Attestation", signed);
  if (!bad.ok) throw new OpenEntityError("invalid_input", `Attestation: ${bad.errors.join("; ")}`);
  return signed;
}
async function signRevocation(kp, attested, o = {}) {
  const created = ts((o.now ?? /* @__PURE__ */ new Date()).getTime());
  return signObject(
    {
      spec: SPEC,
      type: "Revocation",
      issuer: o.issuer ?? kp.did,
      attestation_sha256: typeof attested === "string" ? attested : await sha256Hex(canonicalize(attested)),
      ...o.reason ? { reason: o.reason } : {},
      created
    },
    kp,
    created,
    issuerMethod(kp, o)
  );
}
var multikey = (publicKey) => didKeyFromPublicKey(publicKey).slice("did:key:".length);
function buildDidDocument(did, publicKey, keyId = "key-1") {
  const vm = `${did}#${keyId}`;
  return {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
    id: did,
    verificationMethod: [{ id: vm, type: "Multikey", controller: did, publicKeyMultibase: multikey(publicKey) }],
    assertionMethod: [vm],
    authentication: [vm]
  };
}
function buildOpenEntityJson(did, publicKey, o) {
  return {
    spec: SPEC,
    eid: did,
    name: o.name,
    description: o.description,
    keys: [{ id: `${did}#${o.keyId ?? "key-1"}`, type: "Multikey", publicKeyMultibase: multikey(publicKey) }],
    operator: o.operator ?? { kind: "organization", name: o.name, custody: "operator", can_change: [] },
    ...o.extensions ? { extensions: o.extensions } : {}
  };
}

// src/registry.ts
async function rotate(o) {
  const registry = (o.registry ?? "https://openentity.org").replace(/\/+$/, "");
  const call = async (path2, init) => {
    const r = await fetch(registry + path2, init);
    const text = await r.text();
    if (!r.ok) throw registryError(r.status, path2, text);
    return JSON.parse(text);
  };
  const next = o.successor ?? await generateKeyPair();
  const prevDoc = await call(`/v1/entities/${o.previous.did}/document`);
  const { link, document } = await buildRotation(o.previous, next, successorDocument(prevDoc, next), { basis: o.basis });
  const { stamp_bits } = await call("/v1/spec");
  const response = await call("/v1/continuity", {
    method: "POST",
    headers: { "content-type": "application/json", "x-oe-stamp": await mintStamp(stamp_bits, next.did) },
    body: JSON.stringify({ link, document })
  });
  return { successor: next, link, document, response };
}
var CLIENTS = ["adk", "crewai", "goose", "langchain", "mastra", "moltbotden", "openai-agents", "ui-tars", "vercel-ai", "cli", "other"];
async function registryJson(url, init) {
  const r = await fetch(url, init);
  const text = await r.text();
  if (!r.ok) throw registryError(r.status, url, text);
  return JSON.parse(text);
}
async function adopt(kp, o) {
  if (o.client && !CLIENTS.includes(o.client)) throw new OpenEntityError("invalid_input", `client must be one of ${CLIENTS.join(", ")}`);
  const registry = (o.registry ?? "https://openentity.org").replace(/\/+$/, "");
  const created = nowSeconds();
  const document = await signObject(
    buildDocument({
      kp,
      name: o.name,
      description: o.description ?? "An Open Entity adopted through the TypeScript SDK.",
      created,
      extra: { declaration: { version: DECLARATION_VERSION, sha256: DECLARATION_SHA256, url: `${registry}/v1/entities/${kp.did}/declaration` } }
    }),
    kp,
    created
  );
  const declaration = await signObject(buildDeclaration({ eid: kp.did, name: o.name, created }), kp, created);
  const { stamp_bits } = await registryJson(`${registry}/v1/spec`);
  const post = async (path2, body) => registryJson(registry + path2, { method: "POST", headers: { "content-type": "application/json", "x-oe-stamp": await mintStamp(stamp_bits, kp.did) }, body: JSON.stringify(body) });
  const response = await post("/v1/adopt", { document, declaration, ...o.client ? { client: o.client } : {} });
  const at = nowSeconds();
  const entry = await signObject({
    spec: SPEC,
    type: "RecordEntry",
    eid: kp.did,
    seq: 1,
    prev: null,
    kind: "declaration",
    at,
    payload: { declaration_version: DECLARATION_VERSION, sha256: await sha256Hex(canonicalize(declaration)) }
  }, kp, at);
  const recordPushed = await post(`/v1/entities/${kp.did}/record`, { entries: [entry] }).then(() => true, () => false);
  return { response, did: kp.did, document, declaration, recordEntry: entry, recordPushed };
}
var MOLTBOTDEN = "did:web:moltbotden.com";
var CLAWGRC = "did:web:api.clawgrc.com";
var SMA = ["did:web:securemyagent.ai", "did:pkh:eip155:8453:0x62fef02E2859726EC1c0B534853Ad2cdd5FdDE1a"];
var TIER = "trust_tier";
var POSTURE = "custom:securemyagent:security_posture";
var VIOLATION = "custom:clawgrc:violation";
var ACCEPT = { [TIER]: [MOLTBOTDEN, CLAWGRC], [POSTURE]: SMA, [VIOLATION]: [CLAWGRC] };
var TRUST_CACHE_MS = 3e5;
var trustCache = /* @__PURE__ */ new Map();
var clearTrustCache = () => trustCache.clear();
function didWebResolver(fetchJson = registryJson) {
  return async (did) => {
    if (!did.startsWith("did:web:")) return defaultResolver(did);
    const doc = await fetchJson(didWebUrl(did));
    if (doc.id !== did) throw new OpenEntityError("verification_failed", `${did} document names ${doc.id}`);
    const ed255194 = [];
    for (const vm of doc.verificationMethod ?? []) {
      try {
        ed255194.push(publicKeyFromDidKey("did:key:" + vm.publicKeyMultibase));
      } catch {
      }
    }
    return { ed25519: ed255194 };
  };
}
async function trust(eid, o = {}) {
  const registry = (o.registry ?? "https://openentity.org").replace(/\/+$/, "");
  const key = `${registry} ${eid}`, hit = trustCache.get(key);
  if (hit && Date.now() - hit.at < TRUST_CACHE_MS) return hit.report;
  try {
    const report = await readTrust(eid, registry, (o.now ?? /* @__PURE__ */ new Date()).getTime(), o.fetchJson ?? registryJson, o.resolver ?? didWebResolver(o.fetchJson));
    trustCache.set(key, { at: Date.now(), report });
    return report;
  } catch (e) {
    return { eid, ok: false, error: e.message, withdrawn: false, trustTier: {}, securityPosture: null, violations: [], revocations: [] };
  }
}
async function readTrust(eid, base2, now, get, resolver) {
  if (!eid.startsWith("did:")) throw new OpenEntityError("invalid_input", "eid must be a DID");
  const ent = await get(`${base2}/v1/entities/${eid}`);
  if (ent.eid !== eid) throw new OpenEntityError("verification_failed", `registry answered for ${ent.eid}`);
  const rows = (await get(`${base2}/v1/entities/${eid}/attestations`)).attestations;
  const report = { eid, ok: true, level: ent.level, withdrawn: !!ent.withdrawn, trustTier: {}, securityPosture: null, violations: [], revocations: [] };
  for (const r of [...rows].sort((x, y) => y.attestation.created > x.attestation.created ? 1 : -1)) {
    const a = r.attestation, ct = a.claim_type;
    if (!(ACCEPT[ct] ?? []).some((i) => i.toLowerCase() === String(a.issuer).toLowerCase())) continue;
    if (r.inherited_from && ct !== VIOLATION) continue;
    const sha = r.sha256;
    if (a.subject !== (r.inherited_from ?? eid) || await sha256Hex(canonicalize(a)) !== sha) throw new OpenEntityError("verification_failed", `attestation ${sha} does not match what the registry served`);
    const v = await verifyObject(a, resolver);
    if (!v.ok || v.signer !== a.issuer) throw new OpenEntityError("verification_failed", `attestation ${sha}: ${v.error ?? `signed by ${v.signer}`}`);
    const rv = r.revocation;
    if (rv) {
      const rvv = await verifyObject(rv, resolver);
      if (!rvv.ok || rvv.signer !== a.issuer || rv.attestation_sha256 !== sha) throw new OpenEntityError("verification_failed", `revocation of ${sha}: ${rvv.error ?? `signed by ${rvv.signer}`}`);
      report.revocations.push({ sha256: sha, claim_type: ct, issuer: a.issuer, reason: rv.reason, at: rv.created });
    } else if (r.revoked_at) throw new OpenEntityError("verification_failed", `registry reports a revocation of ${sha} it does not carry`);
    if (rv || Date.parse(a.expires) <= now) continue;
    const c = a.claim;
    if (ct === TIER) report.trustTier[a.issuer] ??= c.tier;
    else if (ct === POSTURE) report.securityPosture ??= c;
    else report.violations.push({ issuer: a.issuer, severity: c.severity, policy: c.policy, observed_at: c.observed_at, sha256: sha });
  }
  return report;
}

// src/merkle.ts
import { ed25519 as ed255192 } from "@noble/curves/ed25519.js";
var leafHashSync = (b) => sha256Sync(concat(Uint8Array.of(0), b));
var nodeHashSync = (l, r) => sha256Sync(concat(Uint8Array.of(1), l, r));
var split = (n) => {
  let k = 1;
  while (k << 1 < n) k <<= 1;
  return k;
};
function mth(d) {
  if (d.length === 0) return sha256Sync(new Uint8Array());
  if (d.length === 1) return d[0];
  const k = split(d.length);
  return nodeHashSync(mth(d.slice(0, k)), mth(d.slice(k)));
}
function path(m, d) {
  if (d.length <= 1) return [];
  const k = split(d.length);
  return m < k ? [...path(m, d.slice(0, k)), mth(d.slice(k))] : [...path(m - k, d.slice(k)), mth(d.slice(0, k))];
}
function subproof(m, d, b) {
  if (m === d.length) return b ? [] : [mth(d)];
  const k = split(d.length);
  return m <= k ? [...subproof(m, d.slice(0, k), b), mth(d.slice(k))] : [...subproof(m - k, d.slice(k), false), mth(d.slice(0, k))];
}
async function leafHash(leafBytes) {
  return leafHashSync(leafBytes);
}
async function nodeHash(l, r) {
  return nodeHashSync(l, r);
}
async function merkleRoot(leafHashes) {
  return mth(leafHashes);
}
async function inclusionProof(index, leafHashes) {
  if (!Number.isInteger(index) || index < 0 || index >= leafHashes.length) throw new RangeError("index out of range");
  return path(index, leafHashes);
}
async function verifyInclusion(index, size, leaf, proof, root) {
  if (!Number.isInteger(index) || !Number.isInteger(size) || index < 0 || index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if (fn & 1 || fn === sn) {
      r = nodeHashSync(p, r);
      while (!(fn & 1) && fn !== 0) fn >>= 1, sn >>= 1;
    } else r = nodeHashSync(r, p);
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && equal(r, root);
}
async function consistencyProof(m, leafHashes) {
  if (!Number.isInteger(m) || m < 1 || m > leafHashes.length) throw new RangeError("m out of range");
  return subproof(m, leafHashes, true);
}
async function verifyConsistency(m, n, rootM, rootN, proof) {
  if (!Number.isInteger(m) || !Number.isInteger(n) || m < 1 || m > n) return false;
  if (m === n) return proof.length === 0 && equal(rootM, rootN);
  if (proof.length === 0) return false;
  const p = (m & m - 1) === 0 ? [rootM, ...proof] : proof;
  let fn = m - 1;
  let sn = n - 1;
  while (fn & 1) fn >>= 1, sn >>= 1;
  let fr = p[0];
  let sr = p[0];
  for (const c of p.slice(1)) {
    if (sn === 0) return false;
    if (fn & 1 || fn === sn) {
      fr = nodeHashSync(c, fr);
      sr = nodeHashSync(c, sr);
      while (!(fn & 1) && fn !== 0) fn >>= 1, sn >>= 1;
    } else sr = nodeHashSync(sr, c);
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && equal(fr, rootM) && equal(sr, rootN);
}
function logLeaf(type, eid, objectSha256, receivedAt) {
  return { type, eid, object_sha256: objectSha256, received_at: receivedAt };
}
var NOTE_DASH = "\u2014";
function checkpointBody(origin, size, rootHash) {
  return `${origin}
${size}
${b64(rootHash)}
`;
}
var noteKeyId = (keyName, pk) => sha256Sync(concat(utf8(keyName), Uint8Array.of(10, 1), pk)).slice(0, 4);
async function signNote(body, keyName, kp) {
  if (!body.endsWith("\n")) throw new OpenEntityError("invalid_input", "note body must end with a newline");
  if (!keyName || /[\s+]/.test(keyName)) throw new OpenEntityError("invalid_input", "invalid note key name");
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, utf8(body)));
  return `${body}
${NOTE_DASH} ${keyName} ${b64(concat(noteKeyId(keyName, kp.publicKey), sig))}
`;
}
function noteVkey(keyName, publicKey) {
  return `${keyName}+${toHex(noteKeyId(keyName, publicKey))}+${b64(concat(Uint8Array.of(1), publicKey))}`;
}
async function verifyNote(note, keyName, publicKey) {
  const i = note.lastIndexOf("\n\n");
  if (i < 0 || !note.endsWith("\n")) return false;
  const text = utf8(note.slice(0, i + 1));
  const id = noteKeyId(keyName, publicKey);
  for (const line of note.slice(i + 2, -1).split("\n")) {
    const prefix = `${NOTE_DASH} ${keyName} `;
    if (!line.startsWith(prefix)) continue;
    let raw;
    try {
      raw = unb64(line.slice(prefix.length));
    } catch {
      continue;
    }
    if (raw.length === 68 && equal(raw.slice(0, 4), id) && ed255192.verify(raw.slice(4), text, publicKey, { zip215: false }))
      return true;
  }
  return false;
}

// src/client.ts
var DEFAULT_REGISTRY = "https://openentity.org";
var base = (registry) => (registry ?? DEFAULT_REGISTRY).replace(/\/+$/, "");
async function postSigned(registry, path2, body, kp, bits) {
  bits ??= (await registryJson(`${registry}/v1/spec`)).stamp_bits;
  return registryJson(registry + path2, { method: "POST", headers: { "content-type": "application/json", "x-oe-stamp": await mintStamp(bits, kp.did) }, body: JSON.stringify(body) });
}
async function withdraw(kp, o = {}) {
  const registry = base(o.registry);
  const name = o.name ?? (await registryJson(`${registry}/v1/entities/${kp.did}`)).document.name;
  const w = await signObject({ spec: SPEC, type: "Withdrawal", eid: kp.did, declaration_version: DECLARATION_VERSION, name, created: nowSeconds(), nonce: randomNonce() }, kp);
  return postSigned(registry, "/v1/withdraw", w, kp);
}
async function record(kp, entries, o = {}) {
  const registry = base(o.registry);
  const head = (await registryJson(`${registry}/v1/entities/${kp.did}/record?after=0`)).head;
  let seq = head ? head.seq : 0, prev = head ? head.hash : null;
  const signed = [];
  for (const [kind, payload] of entries) {
    const at = nowSeconds();
    const e = await signObject({ spec: SPEC, type: "RecordEntry", eid: kp.did, seq: ++seq, prev, kind, at, payload }, kp, at);
    signed.push(e);
    prev = await sha256Hex(canonicalize(e));
  }
  const bits = (await registryJson(`${registry}/v1/spec`)).stamp_bits;
  for (let i = 0; i < signed.length; i += 100) await postSigned(registry, `/v1/entities/${kp.did}/record`, { entries: signed.slice(i, i + 100) }, kp, bits);
  return { accepted: signed.length, entries: signed };
}
var DISPUTE_REASONS = ["impersonation", "illegal_content", "inaccurate", "other"];
async function dispute(kp, o) {
  if (!DISPUTE_REASONS.includes(o.reason)) throw new OpenEntityError("invalid_input", `reason must be one of ${DISPUTE_REASONS.join(", ")}`);
  if (o.objectSha256 !== void 0 && !/^[0-9a-f]{64}$/.test(o.objectSha256)) throw new OpenEntityError("invalid_input", "object_sha256 must be 64 lowercase hex characters");
  const d = await signObject({
    spec: SPEC,
    type: "Dispute",
    issuer: kp.did,
    subject: o.subject,
    ...o.objectSha256 ? { object_sha256: o.objectSha256 } : {},
    reason: o.reason,
    statement: o.statement,
    created: nowSeconds(),
    nonce: randomNonce()
  }, kp);
  return postSigned(base(o.registry), "/v1/disputes", d, kp);
}
async function find(o = {}) {
  const qs = new URLSearchParams();
  for (const [k, v] of [["capability", o.capability], ["q", o.q], ["alias_type", o.aliasType], ["level", o.level]]) if (v) qs.set(k, v);
  return registryJson(`${base(o.registry)}/v1/entities?${qs}`);
}
async function present(kp, o) {
  let attestations = [];
  if (o.registry) {
    const rows = (await registryJson(`${base(o.registry)}/v1/entities/${kp.did}/attestations`)).attestations ?? [];
    attestations = rows.filter((r) => !r.expired && !r.revoked_at && !r.inherited_from).map((r) => r.attestation).slice(0, 20);
  }
  return buildPresentation(kp, { audience: o.audience, nonce: o.nonce, attestations });
}

// src/httpsig.ts
import { ed25519 as ed255193 } from "@noble/curves/ed25519.js";
var didWebKeys = /* @__PURE__ */ new Map();
var DID_CACHE_MS = 6e5;
var DID_REFETCH_MS = 3e4;
async function didJson(url) {
  const r = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(5e3), headers: { accept: "application/did+json, application/json" } });
  if (!r.ok) throw new Error(`${url} answered ${r.status}`);
  return r.json();
}
function ed25519Methods(did, doc) {
  if (doc?.id !== did) throw new Error(`${did} document names ${doc?.id}`);
  const keys = /* @__PURE__ */ new Map();
  for (const vm of Array.isArray(doc.verificationMethod) ? doc.verificationMethod : []) {
    if (typeof vm?.id !== "string") continue;
    try {
      const jwk = vm.publicKeyJwk;
      const key = vm.type === "Multikey" ? publicKeyFromDidKey("did:key:" + vm.publicKeyMultibase) : vm.type === "JsonWebKey" && jwk?.kty === "OKP" && jwk.crv === "Ed25519" && b64url(unb64url(jwk.x)) === jwk.x ? unb64url(jwk.x) : void 0;
      if (key?.length === 32) keys.set(vm.id.startsWith("#") ? did + vm.id : vm.id, key);
    } catch {
    }
  }
  return keys;
}
async function didWebKey(keyid, fetchJson) {
  const did = keyid.split("#")[0];
  const hit = didWebKeys.get(did), age = hit ? Date.now() - hit.at : Infinity;
  if (hit && age < DID_CACHE_MS && (hit.keys.has(keyid) || age < DID_REFETCH_MS)) return hit.keys.get(keyid);
  const keys = ed25519Methods(did, await fetchJson(didWebUrl(did)));
  didWebKeys.set(did, { at: Date.now(), keys });
  return keys.get(keyid);
}
var HTTPSIG_SKEW = 5;
var contentDigest = (body) => `sha-256=:${b64(sha256Sync(body))}:`;
function httpSigBase(method, url, components, digest, params) {
  const value = { "@method": method.toUpperCase(), "@target-uri": url, "content-digest": digest };
  return utf8([...components.map((c) => `"${c}": ${value[c]}`), `"@signature-params": ${params}`].join("\n"));
}
async function signRequest(o) {
  const seed = o.privateKey instanceof Uint8Array ? o.privateKey : unb64url(o.privateKey.privateJwk.d);
  const created = o.created ?? Math.floor(Date.now() / 1e3);
  const nonce = o.nonce ?? b64url(crypto.getRandomValues(new Uint8Array(16)));
  const out = {};
  const comps = ["@method", "@target-uri"];
  if (o.body?.length) {
    out["Content-Digest"] = contentDigest(o.body);
    comps.push("content-digest");
  }
  const params = `(${comps.map((c) => `"${c}"`).join(" ")});created=${created};expires=${created + (o.expiresIn ?? 60)};nonce="${nonce}";keyid="${o.did}";alg="ed25519"`;
  const sig = ed255193.sign(httpSigBase(o.method, o.url, comps, out["Content-Digest"], params), seed);
  out["Signature-Input"] = `sig1=${params}`;
  out["Signature"] = `sig1=:${b64(sig)}:`;
  return out;
}
async function verifyRequest(o) {
  const fail2 = (code) => {
    throw new HttpSigError(code);
  };
  const h = Object.fromEntries(Object.entries(o.headers).map(([k, v]) => [k.toLowerCase(), v]));
  const maxAge = o.maxAge ?? 300;
  const body = o.body ?? new Uint8Array();
  if (!h["signature-input"] || !h["signature"]) fail2("missing_headers");
  const m = /(?:^|,)\s*sig1=(\(([^)]*)\)((?:;[a-z]+=(?:\d+|"[^"]*"))*))/.exec(h["signature-input"]);
  const s = /(?:^|,)\s*sig1=:([A-Za-z0-9+/]+={0,2}):/.exec(h["signature"]);
  if (!m || !s) return fail2("missing_headers");
  const params = m[1];
  const comps = [...m[2].matchAll(/"([^"]*)"/g)].map((x) => x[1]);
  const p = {};
  for (const [, k, v] of m[3].matchAll(/;([a-z]+)=(\d+|"[^"]*")/g)) p[k] = v.startsWith('"') ? v.slice(1, -1) : Number(v);
  if (p.alg !== "ed25519") fail2("unknown_alg");
  const keyid = String(p.keyid ?? "");
  const did = keyid.split("#")[0];
  let pub;
  if (keyid.startsWith("did:web:")) {
    if (!/#[^#]+$/.test(keyid) || !(o.allowDidWeb ?? []).includes(did)) fail2("bad_keyid");
  } else {
    try {
      pub = publicKeyFromDidKey(keyid);
      if (didKeyFromPublicKey(pub) !== keyid) throw 0;
    } catch {
      return fail2("bad_keyid");
    }
  }
  if (typeof p.created !== "number" || typeof p.expires !== "number") fail2("missing_headers");
  const created = p.created, expires = p.expires;
  const nonce = String(p.nonce ?? "");
  if (nonce.length < 22) fail2("missing_nonce");
  if (comps[0] !== "@method" || comps[1] !== "@target-uri" || comps.length > 3 || comps.length === 3 && comps[2] !== "content-digest") fail2("missing_headers");
  let digest;
  if (body.length || comps.includes("content-digest")) {
    digest = h["content-digest"];
    if (!comps.includes("content-digest") || digest !== contentDigest(body)) fail2("digest_mismatch");
  }
  const now = o.now ?? Math.floor(Date.now() / 1e3);
  if (created > now + HTTPSIG_SKEW) fail2("created_in_future");
  if (now - created > maxAge) fail2("created_too_old");
  if (expires < now) fail2("expired");
  if (expires - created > maxAge) fail2("lifetime_too_long");
  if (!pub) pub = await didWebKey(keyid, o.fetchJson ?? didJson).catch(() => void 0);
  if (!pub) return fail2("bad_keyid");
  let ok = false;
  try {
    ok = ed255193.verify(unb64(s[1]), httpSigBase(o.method, o.url, comps, digest, params), pub);
  } catch {
  }
  if (!ok) fail2("bad_signature");
  return { did, keyid, created, expires, nonce };
}

// src/owner.ts
import { p256 } from "@noble/curves/nist.js";
var RP_ID = "account.openentity.org";
var DAY = 86400;
var WEEK = 7 * DAY;
var MAX_TTL = 600;
var HALF_N = p256.Point.Fn.ORDER >> 1n;
var REQUEST_ID = /^[A-Za-z0-9:._-]{1,128}$/;
var HEX64 = /^[0-9a-f]{64}$/;
var DID = /^did:[a-z0-9]+:[A-Za-z0-9._%:-]*[A-Za-z0-9._%-]$/;
var Fail = class {
  code;
  message;
  constructor(code, message) {
    this.code = code;
    this.message = message;
  }
};
var fail = (code, message) => {
  throw new Fail(code, message);
};
var isObj = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
var exactKeys = (o, keys) => Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));
var isUint = (v) => Number.isSafeInteger(v) && v >= 0;
function b64u(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null;
  const b = unb64url(s);
  return b64url(b) === s ? b : null;
}
function base32(b) {
  const A = "abcdefghijklmnopqrstuvwxyz234567";
  let out = "", bits = 0, value = 0;
  for (const x of b) {
    value = value << 8 | x;
    bits += 8;
    while (bits >= 5) out += A[value >> (bits -= 5) & 31];
    value &= (1 << bits) - 1;
  }
  return bits ? out + A[value << 5 - bits & 31] : out;
}
function plainJson(v, ints = true) {
  if (typeof v === "number") return !ints || Number.isSafeInteger(v) ? null : `number ${v} is not an integer within 2^53`;
  if (typeof v === "string") return /[\uD800-\uDFFF]/u.test(v) ? "string has a lone surrogate" : null;
  if (Array.isArray(v)) for (const x of v) {
    const e = plainJson(x, ints);
    if (e) return e;
  }
  else if (isObj(v)) for (const [k, x] of Object.entries(v)) {
    const e = plainJson(k, ints) ?? plainJson(x, ints);
    if (e) return e;
  }
  return null;
}
function jwkPoint(j) {
  if (!isObj(j) || !exactKeys(j, ["kty", "crv", "x", "y"]) || j.kty !== "EC" || j.crv !== "P-256") return null;
  const x = b64u(j.x), y = b64u(j.y);
  if (x?.length !== 32 || y?.length !== 32) return null;
  const pub = concat(Uint8Array.of(4), x, y);
  try {
    p256.Point.fromBytes(pub).assertValidity();
    return pub;
  } catch {
    return null;
  }
}
var thumbprint = (j) => b64url(sha256Sync(`{"crv":"P-256","kty":"EC","x":"${j.x}","y":"${j.y}"}`));
function derToRaw(der) {
  if (der.length < 8 || der[0] !== 48 || der[1] !== der.length - 2 || der[1] > 127) return null;
  const out = new Uint8Array(64);
  let i = 2;
  for (const at of [0, 32]) {
    if (der[i] !== 2) return null;
    const len = der[i + 1], v = der.subarray(i + 2, i + 2 + len);
    if (len < 1 || len > 33 || v.length !== len || v[0] & 128 || len > 1 && v[0] === 0 && !(v[1] & 128) || len === 33 && v[0]) return null;
    const int = len === 33 ? v.subarray(1) : v;
    out.set(int, at + 32 - int.length);
    i += 2 + len;
  }
  return i === der.length ? out : null;
}
function ecdsa(raw, msg, pub, prehash, lowS) {
  if (lowS && BigInt("0x" + toHex(raw.subarray(32))) > HALF_N) return false;
  try {
    return p256.verify(raw, msg, pub, { prehash, lowS: false, format: "compact" });
  } catch {
    return false;
  }
}
function checkSignature(cred, s, digest, o) {
  if (s.form !== cred.type) fail("bad_signature", `a ${cred.type} key cannot present a ${String(s.form)} signature`);
  const pub = jwkPoint(cred.jwk);
  const sig = b64u(s.signature);
  if (s.form === "p256") {
    if (sig.length !== 64 || !ecdsa(sig, digest, pub, false, o.lowS)) fail("bad_signature", "p256 signature does not verify");
    return 0;
  }
  const authData = b64u(s.authenticator_data), clientRaw = b64u(s.client_data_json);
  let client;
  try {
    client = parseJson(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(clientRaw));
  } catch {
    fail("bad_webauthn", "clientDataJSON is not JSON");
  }
  if (plainJson(client, false)) fail("bad_webauthn", "clientDataJSON has a lone surrogate");
  if (!isObj(client) || client.type !== "webauthn.get") fail("bad_webauthn", "clientDataJSON type must be webauthn.get");
  const c = client;
  if (c.challenge !== b64url(digest)) fail("bad_webauthn", "challenge is not the digest");
  if (typeof c.origin !== "string" || !o.origins.includes(c.origin)) fail("bad_webauthn", `origin ${String(c.origin)} is not accepted`);
  if (c.crossOrigin === true) fail("bad_webauthn", "cross-origin assertions are not accepted");
  if (authData.length < 37 || !equal(authData.subarray(0, 32), sha256Sync(o.rpId))) fail("bad_webauthn", `rpIdHash is not SHA-256(${o.rpId})`);
  if ((authData[32] & 5) !== 5) fail("bad_webauthn", "user presence and user verification flags must be set");
  const raw = derToRaw(sig);
  if (!raw || !ecdsa(raw, concat(authData, sha256Sync(clientRaw)), pub, true, o.lowS)) fail("bad_signature", "webauthn signature does not verify");
  return new DataView(authData.buffer, authData.byteOffset).getUint32(33);
}
function signedShape(s) {
  if (s.form !== "p256" && s.form !== "webauthn") return "form must be p256 or webauthn";
  if (!b64u(s.signature)) return "signature must be base64url";
  if (s.form === "webauthn" && (!b64u(s.authenticator_data) || !b64u(s.client_data_json))) return "webauthn needs authenticator_data and client_data_json in base64url";
  return null;
}
function approvalDigest(a) {
  const e = approvalFieldsError(a);
  if (e) throw new OpenEntityError("invalid_input", e);
  return sha256Sync(["approval/2.0", a.verifier_did, a.owner_did, a.request_id, a.payload_digest, a.decision, String(a.expires_at)].join("|"));
}
function approvalFieldsError(a) {
  if (typeof a.verifier_did !== "string" || !DID.test(a.verifier_did)) return "verifier_did must be a DID";
  if (typeof a.owner_did !== "string" || !DID.test(a.owner_did)) return "owner_did must be a DID";
  if (typeof a.request_id !== "string" || !REQUEST_ID.test(a.request_id)) return "request_id must be 1 to 128 of [A-Za-z0-9:._-]";
  if (typeof a.payload_digest !== "string" || !HEX64.test(a.payload_digest)) return "payload_digest must be 64 lowercase hex";
  if (a.decision !== "approve" && a.decision !== "deny") return "decision must be approve or deny";
  if (!isUint(a.expires_at)) return "expires_at must be unix seconds";
  return null;
}
function payloadDigest(summary) {
  const e = plainJson(summary);
  if (e) throw new OpenEntityError("invalid_input", e);
  return toHex(sha256Sync(canonicalize(summary)));
}
function verifyApproval(approval, o) {
  try {
    if (!isObj(approval)) fail("malformed", "approval must be an object");
    const a = approval;
    if (a.version !== "approval/2.0") fail("bad_version", `version ${String(a.version)} is not approval/2.0`);
    const shape = approvalFieldsError(a) ?? (typeof a.device_id === "string" ? signedShape(a) : "device_id must be a string");
    if (shape) fail("malformed", shape);
    const now = o.now ?? Math.floor(Date.now() / 1e3);
    if (a.verifier_did !== o.verifierDid) fail("wrong_verifier", `approval is for ${String(a.verifier_did)}`);
    if (a.owner_did !== o.ownerDid || a.owner_did !== o.keyLog.did) fail("wrong_owner", "approval names another owner");
    if (o.keyLog.closed) fail("owner_closed", "the owner's key log is closed");
    if (a.request_id !== o.requestId) fail("wrong_request", "the request changed; fetch a new one");
    if (a.payload_digest !== o.payloadDigest) fail("wrong_payload", "payload digest does not match the action");
    if (!(o.decisions ?? ["approve", "deny"]).includes(a.decision)) fail("bad_decision", `decision ${String(a.decision)} is not accepted here`);
    const exp = a.expires_at;
    if (now >= exp) fail("expired", "approval expired");
    if (exp > now + MAX_TTL) fail("expiry_too_far", "expires_at is more than 600 seconds away");
    const cred = o.keyLog.approvers.find((c) => c.kid === a.device_id) ?? (o.allowRoot && o.keyLog.root?.kid === a.device_id ? o.keyLog.root : void 0);
    if (!cred) fail("unknown_key", "device_id is not a current approver in the owner's key log");
    const rpId = o.rpId ?? RP_ID;
    const counter = checkSignature(cred, a, approvalDigest(a), { origins: o.origins ?? [`https://${rpId}`], rpId, lowS: false });
    const stored = o.counter ?? 0;
    if (a.form === "webauthn" && (counter || stored) && counter <= stored) fail("counter_replayed", "signature counter did not increase");
    return { ok: true, kid: cred.kid, counter };
  } catch (x) {
    if (x instanceof Fail) return { ok: false, error: x.code, message: x.message };
    throw x;
  }
}
var BODY = {
  genesis: ["approver", "root"],
  add_approver: ["approver"],
  recover: ["approvers"],
  replace_root: ["root"],
  cancel: ["target"],
  revoke: ["kid"],
  close: []
};
function credential(c, rpId, what) {
  if (!isObj(c)) fail("malformed", `${what} must be a credential object`);
  const k = c;
  if (k.type !== "p256" && k.type !== "webauthn") fail("malformed", `${what}.type must be p256 or webauthn`);
  if (!jwkPoint(k.jwk)) fail("malformed", `${what}.jwk must be exactly {kty: EC, crv: P-256, x, y} with a point on the curve`);
  if (k.kid !== thumbprint(k.jwk)) fail("malformed", `${what}.kid must be the RFC 7638 thumbprint of its jwk`);
  if (k.type === "webauthn" && (!b64u(k.credential_id)?.length || k.rp_id !== rpId)) fail("malformed", `${what} needs a credential_id and rp_id ${rpId}`);
  return k;
}
function parseEntry(line, rpId, first) {
  if (typeof line !== "string") fail("malformed", "entry must be a JSON line");
  let e;
  try {
    e = parseJson(line);
  } catch (x2) {
    fail("malformed", `not JSON: ${x2.message}`);
  }
  const bad = plainJson(e);
  if (bad) fail("malformed", bad);
  if (canonicalize(e) !== line) fail("malformed", "line is not the RFC 8785 form of its entry");
  if (!isObj(e) || !exactKeys(e, ["v", "seq", "prev", "op", "ts", "body", "auth"])) fail("malformed", "entry must have exactly v, seq, prev, op, ts, body, auth");
  const x = e;
  if (x.v !== 1) fail("malformed", "v must be 1");
  if (!isUint(x.seq) || !isUint(x.ts)) fail("malformed", "seq and ts must be unsigned integers");
  if (x.prev !== null && (typeof x.prev !== "string" || !HEX64.test(x.prev))) fail("malformed", "prev must be null or 64 lowercase hex");
  if (typeof x.op !== "string" || !Object.hasOwn(BODY, x.op)) fail("malformed", `unknown op ${String(x.op)}`);
  if (x.op === "genesis" !== first) fail("malformed", "genesis is the first entry and only the first");
  if (!isObj(x.body) || !exactKeys(x.body, BODY[x.op])) fail("malformed", `${String(x.op)} body must have exactly: ${BODY[x.op].join(", ") || "nothing"}`);
  const body = x.body;
  switch (x.op) {
    case "genesis":
      if (credential(body.root, rpId, "root").type !== "webauthn") fail("malformed", "root must be a passkey (webauthn)");
      if (body.approver !== null) credential(body.approver, rpId, "approver");
      break;
    case "add_approver":
      credential(body.approver, rpId, "approver");
      break;
    case "recover":
      if (!Array.isArray(body.approvers) || !body.approvers.length) fail("malformed", "recover needs at least one approver");
      body.approvers.forEach((c, i) => credential(c, rpId, `approvers[${i}]`));
      break;
    case "replace_root":
      if (credential(body.root, rpId, "root").type !== "webauthn") fail("malformed", "root must be a passkey (webauthn)");
      break;
    case "cancel":
      if (typeof body.target !== "string" || !HEX64.test(body.target)) fail("malformed", "target must be 64 lowercase hex");
      break;
    case "revoke":
      if (typeof body.kid !== "string") fail("malformed", "kid must be a string");
      break;
  }
  const auth = x.auth;
  if (!isObj(auth) || typeof auth.kid !== "string") fail("malformed", "auth must be an object with a kid");
  const a = auth;
  const keys = a.form === "webauthn" ? ["kid", "form", "signature", "authenticator_data", "client_data_json"] : ["kid", "form", "signature"];
  const shape = signedShape(a) ?? (exactKeys(a, keys) ? null : `auth must have exactly ${keys.join(", ")}`);
  if (shape) fail("malformed", shape);
  return x;
}
function verifyKeyLog(did, lines, firstSeenAt, opts = {}) {
  const rpId = opts.rpId ?? RP_ID;
  const sig = { origins: opts.origins ?? [`https://${rpId}`], rpId, lowS: true };
  const now = opts.now ?? Math.floor(Date.now() / 1e3);
  const services = (opts.serviceKeys ?? []).map((jwk) => {
    if (!jwkPoint(jwk)) throw new OpenEntityError("invalid_input", "serviceKeys must be P-256 public JWKs {kty, crv, x, y}");
    return { kid: thumbprint(jwk), type: "p256", jwk };
  });
  let seq = 1;
  try {
    if (!Array.isArray(lines) || !lines.length) fail("malformed", "a key log starts with its genesis entry");
    if (!Array.isArray(firstSeenAt) || firstSeenAt.length !== lines.length) fail("bad_first_seen", "one first_seen_at per entry");
    let root, single = false, closed = false, head = "";
    let approvers = [], pending = [];
    const revoked = [];
    const seen = /* @__PURE__ */ new Set();
    const delayed = /* @__PURE__ */ new Map();
    const approver = (kid) => (single ? [root] : approvers).find((c) => c.kid === kid);
    const due = (t) => {
      while (pending.length && pending[0].effective_at <= t) {
        const p = pending.shift();
        if (p.op === "replace_root") root = p.creds[0];
        else {
          for (const c of approvers) revoked.push({ cred: c, at: p.effective_at });
          approvers = p.creds;
          single = false;
        }
      }
    };
    const fresh = (creds) => {
      for (const c of creds) {
        if (seen.has(c.kid)) fail("key_reused", `key ${c.kid} is already in this log`);
        seen.add(c.kid);
      }
    };
    for (let i = 0; i < lines.length; i++) {
      seq = i + 1;
      const t = firstSeenAt[i];
      if (!isUint(t) || t > now || i > 0 && t < firstSeenAt[i - 1]) fail("bad_first_seen", "first_seen_at must be unix seconds, never decreasing, not after now");
      if (i > 0) due(t);
      const e = parseEntry(lines[i], rpId, i === 0);
      if (closed) fail("closed", "the log is closed");
      if (e.seq !== seq) fail("bad_seq", `seq must be ${seq}`);
      if (e.prev !== (i ? head : null)) fail("bad_prev", i ? "prev is not the SHA-256 of the previous entry" : "genesis prev must be null");
      const hash = toHex(sha256Sync(lines[i]));
      const { auth: _auth, ...unsigned } = e;
      const digest = sha256Sync(canonicalize(unsigned));
      const b = e.body, kid = e.auth.kid;
      let signer;
      switch (e.op) {
        case "genesis": {
          if (did !== `did:web:${rpId}:o:${base32(sha256Sync(lines[i]))}`) fail("did_mismatch", "the genesis hash does not match the DID suffix");
          root = b.root;
          const first = b.approver;
          fresh(first ? [root, first] : [root]);
          single = !first;
          approvers = first ? [first] : [];
          signer = (first ?? root).kid === kid ? first ?? root : void 0;
          break;
        }
        case "add_approver":
          fresh([b.approver]);
          signer = approver(kid);
          break;
        case "recover":
          fresh(b.approvers);
          signer = root.kid === kid ? root : void 0;
          break;
        case "replace_root":
          fresh([b.root]);
          signer = root.kid === kid ? root : approver(kid);
          break;
        case "cancel": {
          const op = delayed.get(b.target);
          if (!op) fail("bad_target", "target is not a recover or replace_root in this log");
          signer = approver(kid) ?? revoked.find((r) => r.cred.kid === kid && t < r.at + WEEK)?.cred ?? (op === "recover" && root.kid === kid ? root : void 0);
          break;
        }
        case "revoke":
          if (!approvers.some((c) => c.kid === b.kid)) fail("bad_target", "kid is not a current approver");
          signer = root.kid === kid ? root : approver(kid);
          break;
        case "close":
          signer = services.find((c) => c.kid === kid);
          break;
      }
      if (!signer) fail("unauthorized", `key ${kid} may not sign ${e.op} here`);
      checkSignature(signer, e.auth, digest, sig);
      switch (e.op) {
        case "add_approver":
          approvers = [...approvers, b.approver];
          single = false;
          break;
        case "recover":
          pending.push({ seq, op: "recover", hash, effective_at: t + DAY, creds: b.approvers });
          delayed.set(hash, "recover");
          break;
        case "replace_root":
          if (single) root = b.root;
          else pending.push({ seq, op: "replace_root", hash, effective_at: t + DAY, creds: [b.root] });
          delayed.set(hash, "replace_root");
          break;
        case "cancel":
          pending = pending.filter((p) => p.hash !== b.target);
          break;
        case "revoke": {
          const gone = approvers.find((c) => c.kid === b.kid);
          approvers = approvers.filter((c) => c !== gone);
          revoked.push({ cred: gone, at: t });
          break;
        }
        case "close":
          closed = true;
          pending = [];
          break;
      }
      head = hash;
    }
    due(now);
    return {
      ok: true,
      state: {
        did,
        seq: lines.length,
        head,
        root,
        approvers: single ? [root] : approvers,
        revoked: revoked.map((r) => ({ kid: r.cred.kid, at: r.at })),
        pending: pending.map(({ creds: _c, ...p }) => p),
        closed
      }
    };
  } catch (x) {
    if (x instanceof Fail) return { ok: false, error: x.code, seq, message: x.message };
    throw x;
  }
}

// src/pair.ts
var COLORS = "red orange yellow green blue purple pink brown black white gray gold silver navy olive coral".split(" ");
var NOUNS = "fox kite bear boat star tree fish moon drum frog lamp owl wolf shell crown horse".split(" ");
var PAIR_SAS_WORDS = Object.freeze(Array.from({ length: 256 }, (_, i) => `${COLORS[i >> 4]} ${NOUNS[i & 15]}`));
function pairSas(code, agentDid) {
  const c = String(code).trim().toUpperCase();
  if (!/^OE-[0-9A-Z]{4}-[0-9A-Z]{4}$/.test(c)) throw new OpenEntityError("invalid_input", "pairing code must look like OE-XXXX-XXXX");
  if (!/^did:[a-z0-9]+:[A-Za-z0-9._%:-]*[A-Za-z0-9._%-]$/.test(agentDid)) throw new OpenEntityError("invalid_input", "agentDid must be a DID");
  return [...sha256Sync(`oe-pair-sas/1|${c}|${agentDid}`).subarray(0, 4)].map((b) => PAIR_SAS_WORDS[b]);
}

export {
  OpenEntityError,
  HttpSigError,
  SPEC,
  DECLARATION_VERSION,
  DECLARATION_TEXT,
  DECLARATION_SHA256,
  canonicalize,
  parseJson,
  sha256,
  sha256Hex,
  base58btcEncode,
  base58btcDecode,
  randomNonce,
  nowSeconds,
  keyPairFromJwk,
  generateKeyPair,
  keyPairFromSeed,
  didKeyFromPublicKey,
  publicKeyFromDidKey,
  verificationMethodId,
  normalizeEid,
  hashData,
  signProof,
  signObject,
  verifyProof,
  verifyObject,
  eip712Digest,
  recoverEip712,
  buildDocument,
  buildDeclaration,
  successorDocument,
  buildRotation,
  recordEntryHash,
  validate,
  checkTimestamp,
  mintStamp,
  checkStamp,
  buildPresentation,
  verifyPresentation,
  A2A_EXTENSION_URI,
  a2aExtension,
  agentCard,
  signAttestation,
  signRevocation,
  buildDidDocument,
  buildOpenEntityJson,
  rotate,
  CLIENTS,
  adopt,
  clearTrustCache,
  didWebResolver,
  trust,
  leafHash,
  nodeHash,
  merkleRoot,
  inclusionProof,
  verifyInclusion,
  consistencyProof,
  verifyConsistency,
  logLeaf,
  checkpointBody,
  signNote,
  noteVkey,
  verifyNote,
  DEFAULT_REGISTRY,
  withdraw,
  record,
  DISPUTE_REASONS,
  dispute,
  find,
  present,
  httpSigBase,
  signRequest,
  verifyRequest,
  approvalDigest,
  payloadDigest,
  verifyApproval,
  verifyKeyLog,
  pairSas
};
