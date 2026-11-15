import CryptoKit
import Foundation
import OpenEntityKit
import Testing

// test-vectors/http-signature.json through verifyRequest (the TS and Python suites run the same vectors), the did:web and signer-pin
// cases through an injected fetch (no network), and forged signatures for the guards the vectors do not name.

let sigVectors = (try? vector("http-signature.json")) ?? .null

func headers(_ c: JSONValue) -> [String: String] {
    guard case .object(let m) = c.at("headers") else { return [:] }
    return Dictionary(uniqueKeysWithValues: m.map { ($0.key, $0.value.str) })
}

func verify(_ c: JSONValue, now: Int64, expect: [String]? = nil, allow: [String] = [], resolver: DIDWebResolver? = nil)
    async throws(OpenEntityError) -> VerifiedRequest {
    try await verifyRequest(method: c.at("method").str, url: c.at("url").str, headers: headers(c), body: Data(c.at("body").str.utf8),
                            now: c["now"]?.int ?? now, expectDid: expect, allowDidWeb: allow, resolver: resolver)
}

func code(_ body: () async throws -> VerifiedRequest) async -> String {
    do { _ = try await body(); return "accepted" } catch { return (error as? OpenEntityError)?.code ?? "\(error)" }
}

@Suite("RFC 9421 requests")
struct HTTPSigTests {
    let now = sigVectors.at("now").int
    let did = sigVectors.at("did").str

    @Test(arguments: sigVectors.at("valid").list.map { $0.at("name").str })
    func validVector(_ name: String) async throws {
        let c = try #require(sigVectors.at("valid").list.first { $0.at("name").str == name })
        let v = try await verify(c, now: now)
        #expect(v == VerifiedRequest(did: did, keyid: did, created: c.at("created").int, expires: c.at("created").int + 60, nonce: c.at("nonce").str))
    }

    @Test(arguments: sigVectors.at("invalid").list.map { $0.at("name").str })
    func invalidVector(_ name: String) async throws {
        let c = try #require(sigVectors.at("invalid").list.first { $0.at("name").str == name })
        #expect(await code { try await verify(c, now: now) } == c.at("code").str)
    }

    @Test func headerNamesIgnoreCaseAndMethodCase() async throws {
        let c = sigVectors.at("valid").list[0]
        let lower = Dictionary(uniqueKeysWithValues: headers(c).map { ($0.key.lowercased(), $0.value) })
        let v = try await verifyRequest(method: "post", url: c.at("url").str, headers: lower, body: Data(c.at("body").str.utf8), now: now)
        #expect(v.did == did)
    }

    // ---- forged signatures: the entity throwaway seed signs whatever parameters a case needs.
    static let seed = try! Curve25519.Signing.PrivateKey(rawRepresentation: unhex(try! vector("keys.json").at("entity").at("seed").str))
    static let url = "https://gateway.example.com/v1/tools/call"
    static let body = Data("{}".utf8)
    static let digest = "sha-256=:\(Data(SHA256.hash(data: body)).base64EncodedString()):"
    static let nonce = "AAECAwQFBgcICQoLDA0ODw"

    func params(created: Int64? = nil, expires: Int64? = nil, nonce: String? = nonce, keyid: String? = nil, alg: String = "ed25519",
                comps: String = "\"@method\" \"@target-uri\" \"content-digest\"") -> String {
        let c = created ?? now - 10
        return "(\(comps));created=\(c);expires=\(expires ?? c + 60)" + (nonce.map { ";nonce=\"\($0)\"" } ?? "") + ";keyid=\"\(keyid ?? did)\";alg=\"\(alg)\""
    }

    func forged(_ params: String, covering comps: [String] = ["@method", "@target-uri", "content-digest"]) throws -> [String: String] {
        let lines = comps.map { c in "\"\(c)\": " + (c == "@method" ? "POST" : c == "@target-uri" ? Self.url : Self.digest) } + ["\"@signature-params\": \(params)"]
        let sig = try Self.seed.signature(for: Array(lines.joined(separator: "\n").utf8))
        return ["Content-Digest": Self.digest, "Signature-Input": "sig1=\(params)", "Signature": "sig1=:\(sig.base64EncodedString()):"]
    }

    func check(_ h: [String: String], _ want: String, body: Data = HTTPSigTests.body, maxAge: Int64 = 300) async {
        let got = await code { try await verifyRequest(method: "POST", url: Self.url, headers: h, body: body, now: now, maxAge: maxAge) }
        #expect(got == want)
    }

    @Test func aWellFormedForgeVerifies() async throws { await check(try forged(params()), "accepted") }

    @Test func malformedHeaders() async throws {
        await check([:], "missing_headers")
        var h = try forged(params())
        h["Signature"] = "garbage"
        await check(h, "missing_headers")
        h = try forged(params())
        h["Signature"] = nil
        await check(h, "missing_headers")
    }

    @Test func parametersAreChecked() async throws {
        await check(try forged(params(alg: "rsa-pss-sha512")), "unknown_alg")
        await check(try forged(params(keyid: "did:web:example.com")), "bad_keyid")
        await check(try forged(params(keyid: "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme")), "bad_keyid")  // secp256k1
        await check(try forged(params(nonce: nil)), "missing_nonce")
        await check(try forged(params(nonce: "short")), "missing_nonce")
        await check(try forged(params(created: now - 400, expires: now + 10)), "created_too_old")
        await check(try forged(params(expires: now + 301)), "lifetime_too_long")
        await check(try forged(params(created: now - 10, expires: now - 1)), "expired")
        await check(try forged(params(created: now + 6)), "created_in_future")
        await check(try forged(params(created: now + 5)), "accepted")  // 5 seconds of skew
        await check(try forged(params()), "lifetime_too_long", maxAge: 59)
    }

    @Test func coveredComponentsAreChecked() async throws {
        await check(try forged(params(comps: "\"@target-uri\" \"@method\"")), "missing_headers")
        await check(try forged(params(comps: "\"@method\" \"@target-uri\" \"content-digest\" \"host\"")), "missing_headers")
        // An empty body still needs the digest when the signature covers it; a body needs it covered.
        await check(try forged(params(comps: "\"@method\" \"@target-uri\""), covering: ["@method", "@target-uri"]), "digest_mismatch")
        var h = try forged(params())
        h["Content-Digest"] = nil
        await check(h, "digest_mismatch")
        await check(try forged(params()), "digest_mismatch", body: Data("other".utf8))
    }

    @Test func aRepeatedParameterIsRefused() async throws {
        await check(try forged(params() + ";created=1"), "missing_headers")
    }

    // ---- did:web signers and signer pins, against the vectors' DID documents.
    @Test(arguments: sigVectors.at("did_web").at("valid").list.map { $0.at("name").str })
    func didWebValid(_ name: String) async throws {
        let w = sigVectors.at("did_web"), c = try #require(w.at("valid").list.first { $0.at("name").str == name })
        let web = FakeWeb([w.at("url").str: w.at("document")])
        let v = try await verify(c, now: w.at("now").int, allow: [w.at("did").str], resolver: web.resolver())
        #expect(v.did == w.at("did").str && v.keyid == c.at("keyid").str)
    }

    @Test(arguments: sigVectors.at("did_web").at("invalid").list.map { $0.at("name").str })
    func didWebInvalid(_ name: String) async throws {
        let w = sigVectors.at("did_web"), c = try #require(w.at("invalid").list.first { $0.at("name").str == name })
        let web = FakeWeb([w.at("url").str: w.at("document")])
        #expect(await code { try await verify(c, now: w.at("now").int, allow: [w.at("did").str], resolver: web.resolver()) } == c.at("code").str)
    }

    @Test func aDidWebSignerNeedsAResolverAndAnAllowedDid() async throws {
        let w = sigVectors.at("did_web"), c = w.at("valid").list[0], web = FakeWeb([w.at("url").str: w.at("document")])
        #expect(await code { try await verify(c, now: w.at("now").int, allow: [w.at("did").str]) } == "bad_keyid")
        #expect(await code { try await verify(c, now: w.at("now").int, resolver: web.resolver()) } == "bad_keyid")
        #expect(web.fetched.isEmpty)
    }

    @Test(arguments: sigVectors.at("expect_did").at("requests").at("valid").list.map { $0.at("name").str })
    func pinValid(_ name: String) async throws {
        let e = sigVectors.at("expect_did"), c = try #require(e.at("requests").at("valid").list.first { $0.at("name").str == name })
        let web = FakeWeb([e.at("url").str: e.at("document")])
        let pin = c.at("expect_did").stringValue.map { [$0] } ?? c.at("expect_did").strings
        #expect(try await verify(c, now: e.at("now").int, expect: pin, resolver: web.resolver()).did == c.at("did").str)
    }

    @Test(arguments: sigVectors.at("expect_did").at("requests").at("invalid").list.map { $0.at("name").str })
    func pinInvalid(_ name: String) async throws {
        let e = sigVectors.at("expect_did"), c = try #require(e.at("requests").at("invalid").list.first { $0.at("name").str == name })
        let web = FakeWeb([e.at("url").str: e.at("document")])
        let pin = c.at("expect_did").stringValue.map { [$0] } ?? c.at("expect_did").strings
        #expect(await code { try await verify(c, now: e.at("now").int, expect: pin, resolver: web.resolver()) } == c.at("code").str)
        #expect(web.fetched.isEmpty, "a refused signer causes no fetch")
    }

    @Test func allowDidWebAloneIsNotAPin() async throws {
        let e = sigVectors.at("expect_did"), c = try #require(e.at("requests").at("invalid").list.first { $0.at("name").str == "did-key-under-did-web-pin" })
        let v = try await verify(c, now: e.at("now").int, allow: c.at("expect_did").strings)
        #expect(v.did.hasPrefix("did:key:"))
    }
}

@Suite("verifyAgentForCheckout request")
struct CheckoutRequestTests {
    // The vectors' GET request is signed by the entity key, which is the agent of every checkout-1 cart.
    static let request = sigVectors.at("valid").list.first { $0.at("name").str == "get-empty-body" }!
    static let cart = checkoutVectors.at("cases").list.first { $0.at("name").str == "allow-mandate-covers" }!.at("input").at("cart")
    let now = sigVectors.at("now").int

    func signed(url: String? = nil, method: String? = nil) -> SignedRequest {
        let r = Self.request
        return SignedRequest(method: method ?? r.at("method").str, url: url ?? r.at("url").str, headers: headers(r), body: Data(r.at("body").str.utf8))
    }

    @Test func aVerifiedRequestIdentifiesTheAgent() async {
        let d = await verifyAgentForCheckout(request: signed(), cart: Self.cart, policy: AgentPolicy(), now: now)
        #expect(d.decision == "step_up" && d.reasons == ["no_mandate"])
        #expect(d.evidence.request == "verified" && d.evidence.agentDid == Self.cart.at("agent_did").str)
    }

    @Test func aRequestThatDoesNotVerifyDeniesWithoutLookingAtTheCart() async {
        for bad in [signed(url: "https://evil.example/"), signed(method: "POST")] {
            let d = await verifyAgentForCheckout(request: bad, cart: Self.cart, policy: AgentPolicy(), now: now)
            #expect(d.decision == "deny" && d.reasons == ["request_unverified"] && d.evidence.request == nil)
        }
        let late = await verifyAgentForCheckout(request: signed(), cart: Self.cart, policy: AgentPolicy(), now: now + 1000)
        #expect(late.reasons == ["request_unverified"])
    }

    @Test func aCartForAnotherAgentIsRefused() async {
        let other = Self.cart.at("merchant").str
        guard case .object(let m) = Self.cart else { Issue.record("not an object"); return }
        let cart = JSONValue.object(m.map { $0.key == "agent_did" ? ($0.key, .string(other)) : $0 })
        // merchant == agent is a malformed cart in other ways too; either way the request cannot buy it.
        let d = await verifyAgentForCheckout(request: signed(), cart: cart, policy: AgentPolicy(), now: now)
        #expect(d.decision == "deny")
    }

    @Test func aBadCartDeniesBadCartWhateverTheRequest() async {
        let d = await verifyAgentForCheckout(request: signed(), cart: .object([]), policy: AgentPolicy(), now: now)
        #expect(d.reasons == ["bad_cart"])
    }
}

@Suite("verifyReceiptChain")
struct ReceiptChainTests {
    static let purchase = receiptVectors.at("cases").list[0].at("receipt")

    static func refund(_ id: String, _ total: Int64, _ set: [String: JSONValue] = [:]) -> JSONValue {
        guard case .object(let m) = purchase else { return .null }
        var out = m.filter { $0.key != "proofs" }.map { x -> (key: String, value: JSONValue) in
            switch x.key {
            case "kind": return (x.key, .string("refund"))
            case "receipt_id": return (x.key, .string(id))
            case "refers_to": return (x.key, purchase.at("receipt_id"))
            case "total": return (x.key, .number(Double(total)))
            default: return x
            }
        }
        for (k, v) in set { out = out.map { $0.key == k ? (k, v) : $0 } }
        return .object(out)
    }

    static func outcome(_ r: Result<Int64, ReceiptChainError>) -> String { switch r { case .success(let n): "ok \(n)"; case .failure(let e): e.code } }

    @Test func refundsStayInsideThePurchase() {
        #expect(Self.purchase.at("total").int == 1000)
        let r1 = Self.refund("rc_aaaaaaaaaaaaaaaaaaaaaaaaaa", 600), r2 = Self.refund("rc_bbbbbbbbbbbbbbbbbbbbbbbbbb", 400)
        func run(_ later: [JSONValue], of p: JSONValue = Self.purchase) -> String { Self.outcome(verifyReceiptChain(p, later)) }
        #expect(run([r1, r2]) == "ok 1000")
        #expect(run([]) == "ok 0")
        #expect(run([r1, Self.refund("rc_bbbbbbbbbbbbbbbbbbbbbbbbbb", 401)]) == "over_refund")
        #expect(run([r1, r1]) == "mismatch")
        #expect(run([Self.refund("rc_aaaaaaaaaaaaaaaaaaaaaaaaaa", 600, ["currency": .string("EUR")])]) == "mismatch")
        #expect(run([Self.refund("rc_aaaaaaaaaaaaaaaaaaaaaaaaaa", 600, ["refers_to": .string("rc_cccccccccccccccccccccccccc")])]) == "mismatch")
        #expect(run([], of: r1) == "not_purchase")
        #expect(run([Self.purchase]) == "mismatch")  // a second purchase is not a refund
        #expect(run([.string("x")]) == "malformed")
    }
}
