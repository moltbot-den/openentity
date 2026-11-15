import CryptoKit
import Foundation

// RFC 9421 HTTP message signatures, request side (OEIS-1 11.2 Web Bot Auth, ADR 0005). A port of verifyRequest in
// sdk/ts/src/httpsig.ts: the same checks in the same order with the same failure codes. test-vectors/http-signature.json
// defines it. Profile: ed25519, label sig1, covered ("@method" "@target-uri" ["content-digest"]), keyid = the signer's did:key,
// or `did:web:<host>#<key>` for a did:web signer the verifier allows. Not here: signing requests and verifying signed responses.

/// A request signature that verified: the signer and what the signature said.
public struct VerifiedRequest: Equatable, Sendable {
    /// The signer's DID (the keyid without its `#fragment`).
    public let did: String
    public let keyid: String
    public let created, expires: Int64
    public let nonce: String

    public init(did: String, keyid: String, created: Int64, expires: Int64, nonce: String) {
        self.did = did
        self.keyid = keyid
        self.created = created
        self.expires = expires
        self.nonce = nonce
    }
}

/// Seconds of clock skew allowed on `created`.
let httpSigSkew: Int64 = 5

/// `sha-256=:<base64>:`, the Content-Digest of `body`.
func contentDigest(_ body: some DataProtocol) -> String { "sha-256=:\(Data(sha256(body)).base64EncodedString()):" }

/// Verifies the RFC 9421 signature on a request and returns the signer. Throws `OpenEntityError` whose `code` is the failure:
/// `missing_headers`, `unknown_alg`, `unexpected_signer`, `bad_keyid`, `missing_nonce`, `digest_mismatch`, `created_in_future`,
/// `created_too_old`, `expired`, `lifetime_too_long` or `bad_signature`. Nonce replay tracking is the caller's job.
///
/// `headers` may use any name case. `url` is the absolute target URI as the agent signed it. `expectDid` pins the signer: any
/// other keyid, a did:key included, fails with `unexpected_signer` before any key is read. A did:key keyid verifies offline. A
/// `did:web:<host>#<key>` keyid verifies only when its DID is in `expectDid` or `allowDidWeb` and `resolver` is given: the key
/// must be an Ed25519 method under `authentication` in the DID's did.json. `allowDidWeb` alone is not a pin.
public func verifyRequest(method: String, url: String, headers: [String: String], body: Data = Data(), now: Int64, maxAge: Int64 = 300,
                          expectDid: [String]? = nil, allowDidWeb: [String] = [], resolver: DIDWebResolver? = nil)
    async throws(OpenEntityError) -> VerifiedRequest {
    func fail(_ code: String) -> OpenEntityError { OpenEntityError(code, "RFC 9421 verification failed: \(code)") }
    let h = Dictionary(headers.map { ($0.key.lowercased(), $0.value) }, uniquingKeysWith: { _, last in last })
    let sig = try parseSig1(input: h["signature-input"] ?? "", signature: h["signature"] ?? "")
    if sig.alg != "ed25519" { throw fail("unknown_alg") }
    let did = String(decoding: sig.keyid.utf8.prefix { $0 != UInt8(ascii: "#") }, as: UTF8.self)
    if let pin = expectDid, !pin.contains(where: { same($0, did) }) { throw fail("unexpected_signer") }
    let resolvable = allowDidWeb + (expectDid ?? [])

    var key: [UInt8]?
    if sig.keyid.utf8.starts(with: "did:web:".utf8) {
        guard isDIDWebKeyid(sig.keyid), resolvable.contains(where: { same($0, did) }), resolver != nil else { throw fail("bad_keyid") }
    } else {
        guard let k = try? didKeyPublicKey(sig.keyid), let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: k),
              same(didKey(pub), sig.keyid) else { throw fail("bad_keyid") }
        key = k
    }
    guard let created = sig.created, let expires = sig.expires else { throw fail("missing_headers") }
    if sig.nonce.utf16.count < 22 { throw fail("missing_nonce") }  // 16 bytes in base64url
    let c = sig.components
    guard c.count >= 2, c.count <= 3, same(c[0], "@method"), same(c[1], "@target-uri"), c.count == 2 || same(c[2], "content-digest") else {
        throw fail("missing_headers")
    }
    var digest: String?
    if !body.isEmpty || c.count == 3 {
        digest = h["content-digest"]
        guard c.count == 3, let d = digest, same(d, contentDigest(body)) else { throw fail("digest_mismatch") }
    }
    if created > now + httpSigSkew { throw fail("created_in_future") }
    if now - created > maxAge { throw fail("created_too_old") }
    if expires < now { throw fail("expired") }
    if expires - created > maxAge { throw fail("lifetime_too_long") }
    if key == nil, let resolver {
        key = try? await resolver.keys(for: sig.keyid, authentication: true).first { same($0.id, sig.keyid) }?.key
    }
    guard let key, let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: key) else { throw fail("bad_keyid") }
    var base = ["\"@method\": \(method.uppercased())", "\"@target-uri\": \(url)"]
    if let digest { base.append("\"content-digest\": \(digest)") }
    base.append("\"@signature-params\": \(sig.params)")
    guard pub.isValidSignature(sig.signature, for: Array(base.joined(separator: "\n").utf8)) else { throw fail("bad_signature") }
    return VerifiedRequest(did: did, keyid: sig.keyid, created: created, expires: expires, nonce: sig.nonce)
}

/// `did:web:<host>#<key>`: one non-empty DID part and one non-empty fragment, no second `#`.
private func isDIDWebKeyid(_ s: String) -> Bool {
    let parts = s.utf8.split(separator: UInt8(ascii: "#"), omittingEmptySubsequences: false)
    return parts.count == 2 && parts[0].count > "did:web:".utf8.count && !parts[1].isEmpty
}

/// The checked sig1 members of Signature-Input and Signature.
private struct Sig1 {
    var params = "", keyid = "", nonce = "", alg: String?
    var components: [String] = []
    var created, expires: Int64?
    var signature: [UInt8] = []
}

/// Exactly one sig1 member in each header and no repeated parameter: parsers resolve a duplicate differently. The shapes are
/// those of the TS regexes: `sig1=(` components `)` then `;name=<digits or "string">` parameters; `sig1=:<base64>:`.
private func parseSig1(input: String, signature: String) throws(OpenEntityError) -> Sig1 {
    let bad = OpenEntityError("missing_headers", "Signature-Input and Signature need exactly one well-formed sig1 member")
    let i = Array(input.utf8), s = Array(signature.utf8)
    let ai = members(i), as_ = members(s)
    guard ai.count == 1, as_.count == 1, i[ai[0]...].first == UInt8(ascii: "(") else { throw bad }
    var p = Sig1(), at = ai[0] + 1
    guard let close = i[at...].firstIndex(of: UInt8(ascii: ")")) else { throw bad }
    p.components = quoted(i[at..<close])
    p.params = String(decoding: i[ai[0]...close], as: UTF8.self)
    at = close + 1
    var seen: [String] = []
    while at < i.count, i[at] == UInt8(ascii: ";") {
        var j = at + 1
        while j < i.count, (0x61...0x7A).contains(i[j]) { j += 1 }
        guard j > at + 1, j < i.count, i[j] == UInt8(ascii: "=") else { break }
        let name = String(decoding: i[(at + 1)..<j], as: UTF8.self)
        j += 1
        var text: String, number: Int64?
        if j < i.count, i[j] == UInt8(ascii: "\"") {
            guard let end = i[(j + 1)...].firstIndex(of: UInt8(ascii: "\"")) else { break }
            text = String(decoding: i[(j + 1)..<end], as: UTF8.self)
            j = end + 1
        } else {
            let start = j
            while j < i.count, (0x30...0x39).contains(i[j]) { j += 1 }
            guard j > start else { break }
            text = String(decoding: i[start..<j], as: UTF8.self)
            number = Int64(text)
            if number == nil { throw bad }  // beyond any real timestamp
        }
        if seen.contains(where: { same($0, name) }) { throw bad }
        seen.append(name)
        switch name {
        case "created": p.created = number
        case "expires": p.expires = number
        case "nonce": if number == nil { p.nonce = text }
        case "keyid": if number == nil { p.keyid = text }
        case "alg": if number == nil { p.alg = text }
        default: break
        }
        p.params = String(decoding: i[ai[0]..<j], as: UTF8.self)
        at = j
    }
    // sig1=:<base64>:
    var k = as_[0] + 1
    guard k <= s.count, s[(k - 1)...].first == UInt8(ascii: ":") else { throw bad }
    let start = k
    while k < s.count, isBase64(s[k]) { k += 1 }
    var pad = 0
    while k < s.count, s[k] == UInt8(ascii: "="), pad < 2 { k += 1; pad += 1 }
    guard k > start, k < s.count, s[k] == UInt8(ascii: ":"), let raw = Data(base64Encoded: String(decoding: s[start..<k], as: UTF8.self)) else {
        throw bad
    }
    p.signature = Array(raw)
    return p
}

/// Where each `sig1=` member's value starts: at the start or after a comma and optional whitespace.
private func members(_ b: [UInt8]) -> [Int] {
    let label = Array("sig1=".utf8)
    var out: [Int] = []
    var j = 0
    while j + label.count <= b.count {
        if b[j...].starts(with: label) {
            var k = j - 1
            while k >= 0, [0x20, 0x09].contains(b[k]) { k -= 1 }
            if k < 0 || b[k] == UInt8(ascii: ",") { out.append(j + label.count) }
            j += label.count
        } else {
            j += 1
        }
    }
    return out
}

/// Every `"..."` in `b`.
private func quoted(_ b: ArraySlice<UInt8>) -> [String] {
    var out: [String] = [], open: Int?
    for j in b.indices where b[j] == UInt8(ascii: "\"") {
        if let o = open { out.append(String(decoding: b[(o + 1)..<j], as: UTF8.self)); open = nil } else { open = j }
    }
    return out
}

private func isBase64(_ c: UInt8) -> Bool { isAlnum(c) || c == UInt8(ascii: "+") || c == UInt8(ascii: "/") }
