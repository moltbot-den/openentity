import CryptoKit
import Foundation

// OEIS-1 verification: eddsa-jcs-2022 proofs by did:key (offline) or did:web (through DIDWebResolver), RFC 9162 inclusion
// proofs and the C2SP signed-note checkpoint. A port of sdk/ts/src/core.ts and sdk/ts/src/merkle.ts. EIP-712 proofs (did:pkh)
// need secp256k1 and keccak, which CryptoKit lacks: they report `unsupported`. RFC 9421 HTTP message signatures are a
// server-side profile, not here.

/// Verifies the object's own `proof` by a did:key signer, offline, and returns the signer DID. Throws `verification_failed`,
/// or `unsupported` for EIP-712 proofs and other signers (did:web needs `verifyObject(_:resolver:)`).
public func verifyObject(_ object: JSONValue) throws(OpenEntityError) -> String {
    guard let proof = object["proof"] else { throw failed("missing proof") }
    return try verifyProof(object, proof)
}

/// Verifies the object's own `proof` by a did:key signer (offline) or a did:web signer (its did.json, through `resolver`)
/// and returns the signer DID. Checking that the signer is the object's `issuer` is the caller's job. Throws
/// `verification_failed`, `unresolvable` when the DID document cannot be fetched, or `unsupported`.
public func verifyObject(_ object: JSONValue, resolver: DIDWebResolver) async throws(OpenEntityError) -> String {
    guard let proof = object["proof"] else { throw failed("missing proof") }
    return try await verifyProof(object, proof, resolver: resolver)
}

/// Verifies one eddsa-jcs-2022 proof by a did:key signer over `object` (a ContinuityLink carries several in `proofs`) and
/// returns the signer DID.
public func verifyProof(_ object: JSONValue, _ proof: JSONValue) throws(OpenEntityError) -> String {
    let p = try SignedProof(object, proof)
    return try p.verify(with: [didKeyPublicKey(p.signer)])
}

/// The same for a did:key or did:web signer. Any Ed25519 key of the did:web document verifies, as in the TS and Python SDKs.
public func verifyProof(_ object: JSONValue, _ proof: JSONValue, resolver: DIDWebResolver) async throws(OpenEntityError) -> String {
    let p = try SignedProof(object, proof)
    guard p.signer.utf8.starts(with: "did:web:".utf8) else { return try p.verify(with: [didKeyPublicKey(p.signer)]) }
    return try await p.verify(with: resolver.keys(for: p.method).map(\.key))
}

/// A checked eddsa-jcs-2022 proof: the signer DID, the method it names, the signature and the bytes it covers.
struct SignedProof {
    let signer: String
    let method: String
    let signature: [UInt8]
    let message: [UInt8]

    init(_ object: JSONValue, _ proof: JSONValue) throws(OpenEntityError) {
        guard case .object(let members) = object else { throw failed("not a JSON object") }
        guard case .object(let config) = proof, let method = proof["verificationMethod"]?.stringValue else { throw failed("missing proof") }
        guard let purpose = proof["proofPurpose"]?.stringValue, same(purpose, "assertionMethod") else {
            throw failed("proofPurpose must be assertionMethod")
        }
        let type = proof["type"]?.stringValue ?? ""
        guard same(type, "DataIntegrityProof") else {
            throw OpenEntityError("unsupported", same(type, "EthereumEip712Signature2021")
                ? "EIP-712 proofs need secp256k1 and keccak, which CryptoKit lacks" : "unsupported proof type \(type)")
        }
        guard let suite = proof["cryptosuite"]?.stringValue, same(suite, "eddsa-jcs-2022") else { throw failed("unsupported cryptosuite") }
        guard let value = proof["proofValue"]?.stringValue, value.utf8.first == UInt8(ascii: "z"),
              let signature = base58Decode(value.utf8.dropFirst()) else { throw failed("proofValue must be multibase base58btc") }
        guard signature.count == 64 else { throw failed("signature must be 64 bytes") }
        // eddsa-jcs-2022 hashData: SHA-256(JCS(proof without proofValue)) || SHA-256(JCS(object without proof and proofs)).
        let options = try canonicalize(.object(config.filter { !same($0.key, "proofValue") }))
        let document = try canonicalize(.object(members.filter { !same($0.key, "proof") && !same($0.key, "proofs") }))
        self.signer = String(decoding: method.utf8.prefix { $0 != UInt8(ascii: "#") }, as: UTF8.self)
        self.method = method
        self.signature = signature
        self.message = sha256(Array(options.utf8)) + sha256(Array(document.utf8))
    }

    /// The signer when one of `keys` (Ed25519 public keys) verifies the signature.
    func verify(with keys: [[UInt8]]) throws(OpenEntityError) -> String {
        for key in keys {
            if let k = try? Curve25519.Signing.PublicKey(rawRepresentation: key), k.isValidSignature(signature, for: message) { return signer }
        }
        throw failed("signature does not verify")
    }
}

/// SHA-256(0x00 || leaf bytes): an RFC 9162 leaf hash. Leaf bytes are the UTF-8 of the leaf's RFC 8785 form.
public func leafHash(_ leaf: Data) -> Data { Data(sha256([0] + Array(leaf))) }

/// RFC 9162 section 2.1.3.2: `leaf` is the leaf hash at `index` in a tree of `size` leaves with root `root`.
public func verifyInclusion(index: Int, size: Int, leaf: Data, proof: [Data], root: Data) -> Bool {
    guard index >= 0, index < size else { return false }
    var fn = index, sn = size - 1, r = leaf
    for p in proof {
        if sn == 0 { return false }
        if fn & 1 == 1 || fn == sn {
            r = Data(sha256([1] + Array(p) + Array(r)))
            while fn & 1 == 0 && fn != 0 {
                fn >>= 1
                sn >>= 1
            }
        } else {
            r = Data(sha256([1] + Array(r) + Array(p)))
        }
        fn >>= 1
        sn >>= 1
    }
    return sn == 0 && r == root
}

/// C2SP signed note (the log checkpoint): true when a signature line by `origin` (it starts with U+2014) carries the key id
/// SHA-256(origin + "\n" + 0x01 + publicKey)[0..<4] and a valid Ed25519 signature over the body.
public func verifyNote(note: String, origin: String, publicKey: Data) -> Bool {
    let b = Array(note.utf8)
    guard b.last == 0x0A, let i = b.indices.dropLast().last(where: { b[$0] == 0x0A && b[$0 + 1] == 0x0A }), i + 2 <= b.count - 1,
          let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else { return false }
    let body = Array(b[...i])
    let id = sha256(Array(origin.utf8) + [0x0A, 0x01] + Array(publicKey)).prefix(4)
    let prefix = Array("\u{2014} \(origin) ".utf8)
    for line in b[(i + 2)..<(b.count - 1)].split(separator: 0x0A, omittingEmptySubsequences: false) where line.starts(with: prefix) {
        guard let raw = Data(base64Encoded: String(decoding: line.dropFirst(prefix.count), as: UTF8.self)),
              raw.count == 68, raw.prefix(4).elementsEqual(id) else { continue }
        if key.isValidSignature(raw.dropFirst(4), for: body) { return true }
    }
    return false
}

func failed(_ message: String) -> OpenEntityError { OpenEntityError("verification_failed", message) }

/// The Ed25519 key of a did:key (multicodec 0xed01). did:web goes through DIDWebResolver; other methods are not supported.
func didKeyPublicKey(_ did: String) throws(OpenEntityError) -> [UInt8] {
    let b = Array(did.utf8)
    guard b.starts(with: Array("did:key:".utf8)) else {
        let method = did.split(separator: ":").prefix(2).joined(separator: ":")
        throw OpenEntityError("unsupported", same(method, "did:web") ? "did:web signers verify through verifyObject(_:resolver:)" : "\(method) signers are not supported")
    }
    guard b.count > 9, b[8] == UInt8(ascii: "z"), let raw = base58Decode(b[9...]), raw.count == 34, raw[0] == 0xED, raw[1] == 0x01 else {
        throw failed("not an Ed25519 did:key")
    }
    return Array(raw[2...])
}

/// base58btc (Bitcoin alphabet); nil for any other character.
func base58Decode(_ s: some Collection<UInt8>) -> [UInt8]? {
    let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)
    var little: [UInt8] = []
    for c in s {
        guard var carry = alphabet.firstIndex(of: c) else { return nil }
        for j in little.indices {
            carry += Int(little[j]) * 58
            little[j] = UInt8(carry & 0xFF)
            carry >>= 8
        }
        while carry > 0 {
            little.append(UInt8(carry & 0xFF))
            carry >>= 8
        }
    }
    return [UInt8](repeating: 0, count: s.prefix { $0 == UInt8(ascii: "1") }.count) + little.reversed()
}
