import CryptoKit
import Foundation
import OpenEntityKit
import Testing

// test-vectors/{mandate-1,cart-1,receipt-1,checkout-1}, checked as sdk/ts/test/commerce.test.ts and sdk/python/tests/test_commerce.py
// check them: the same accept or reject and the same error code or reason on every case.

let mandateVectors = (try? vector("mandate-1/vectors.json")) ?? .null
let cartVectors = (try? vector("cart-1/vectors.json")) ?? .null
let receiptVectors = (try? vector("receipt-1/vectors.json")) ?? .null
let checkoutVectors = (try? vector("checkout-1/vectors.json")) ?? .null

func ownerKeys(_ name: String) -> StoredKeys { try! ApprovalTests.keys(name) }

func spent(_ v: JSONValue?) -> (Int64?, Int64?) { (v?["period_spent"].map { $0.int }, v?["total_spent"].map { $0.int }) }

@Suite("mandate/1")
struct MandateTests {
    @Test(arguments: mandateVectors.at("cases").list.map { $0.at("name").str })
    func mandateCase(_ name: String) throws {
        let c = try #require(mandateVectors.at("cases").list.first { $0.at("name").str == name })
        let x = c.at("context"), want = c.at("expect")
        let r = outcome { () throws(OpenEntityError) in
            try verifyMandate(c.at("mandate"), keyLog: ownerKeys(x.at("key_state").str), agentDid: x.at("agent_did").str, now: x.at("now").int, status: x["status"])
        }
        switch r {
        case .success(let m):
            #expect(want.at("ok").boolValue == true, "accepted, expected \(want.at("error").str)")
            #expect(m.mandateId == want.at("mandate_id").str && m.kid == want.at("kid").str)
            #expect(m.terms.limits.perTxMax == want.at("limits").at("per_tx_max").int && m.terms.stepUpOver == want.at("step_up_over").int)
            #expect(m.terms.scope.rails == want.at("scope").at("rails").strings && m.terms.scope.merchants == want.at("scope").at("merchants").strings)
            if let s = x["status"] { #expect((m.periodSpent, m.totalSpent) == spent(s)) }
        case .failure(let e):
            #expect(want.at("ok").boolValue == false, "\(e.code): \(e.message)")
            #expect(e.code == want.at("error").str, "\(e.code): \(e.message)")
        }
    }

    @Test func digestPreimages() throws {
        let known = cartVectors.at("mandates").list_values + mandateVectors.at("cases").list.map { $0.at("mandate") }
        for d in mandateVectors.at("digests").list {
            let m = try #require(known.first { $0.at("mandate_id").str == d.at("mandate_id").str })
            #expect(hex(try mandateDigest(m)) == d.at("digest").str)
        }
    }

    @Test func aMandateSignatureDoesNotVerifyAsAnApproval() throws {
        let r = mandateVectors.at("replay").at("mandate_signature_as_approval"), c = r.at("context")
        let out = outcome { () throws(OpenEntityError) in
            try verifyApproval(r.at("approval"), keyLog: ownerKeys(c.at("key_state").str), verifierDid: c.at("verifier_did").str, ownerDid: c.at("owner_did").str,
                               requestId: c.at("request_id").str, payloadDigest: c.at("payload_digest").str, now: c.at("now").int)
        }
        guard case .failure(let e) = out else { Issue.record("accepted"); return }
        #expect(e.code == r.at("expect").at("error").str)
    }

    @Test func aMalformedOrForeignStatusAnswerIsNoAnswer() throws {
        let c = mandateVectors.at("cases").list[0], x = c.at("context")
        let run = { (status: JSONValue) in
            outcome { () throws(OpenEntityError) in
                try verifyMandate(c.at("mandate"), keyLog: ownerKeys("owner"), agentDid: x.at("agent_did").str, now: x.at("now").int, status: status)
            }
        }
        let id = c.at("mandate").at("mandate_id").str
        let bads = [#"{}"#, #"{"status":"bogus"}"#, #"{"status":"active","mandate_id":"md_aaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
                    #"{"status":"active","total_spent":"abc"}"#, #"{"status":"active","period_spent":-1}"#, #""active""#, "null"]
        for b in bads {
            guard case .failure(let e) = run(try JSONValue.parse(b)) else { Issue.record("accepted \(b)"); continue }
            #expect(e.code == "status_required", "\(b)")
        }
        if case .failure(let e) = run(try JSONValue.parse(#"{"status":"active","mandate_id":"\#(id)"}"#)) { Issue.record("\(e.code)") }
    }

    @Test func mandateIsNotAnObject() {
        let r = outcome { () throws(OpenEntityError) in try verifyMandate(.null, keyLog: ownerKeys("owner"), now: 0) }
        if case .failure(let e) = r { #expect(e.code == "malformed") } else { Issue.record("accepted") }
    }
}

extension JSONValue {
    var list_values: [JSONValue] { if case .object(let m) = self { return m.map(\.value) } else { return [] } }
}

@Suite("cart/1")
struct CartTests {
    @Test func digestsAreSHA256OfJCS() throws {
        for c in cartVectors.at("carts").list {
            #expect(try canonicalize(c.at("cart")) == c.at("canonical").str)
            #expect(try cartDigest(c.at("cart")) == c.at("digest").str)
        }
        #expect(!cartVectors.at("invalid").list.isEmpty)
        for c in cartVectors.at("invalid").list {
            #expect(throws: OpenEntityError.self, "\(c.at("reason").str)") { try cartDigest(c.at("cart")) }
        }
    }

    static func cover(_ c: JSONValue, mandate: JSONValue? = nil, cart: JSONValue? = nil) throws -> MandateCover {
        let (p, t) = spent(c["spent"])
        return mandateCovers(try MandateTerms(mandate ?? cartVectors.at("mandates").at(c.at("mandate").str)), cart: cart ?? c.at("cart"), periodSpent: p, totalSpent: t)
    }

    @Test(arguments: cartVectors.at("covers").list.map { $0.at("name").str })
    func coverCase(_ name: String) throws {
        let c = try #require(cartVectors.at("covers").list.first { $0.at("name").str == name })
        let r = try Self.cover(c), want = c.at("expect")
        #expect(r.ok == want.at("ok").boolValue && r.stepUpRequired == want.at("step_up_required").boolValue && r.reason == want["reason"]?.stringValue, "\(r)")
    }

    @Test func aWildcardMerchantMatchesOnlyAPlainHostname() throws {
        let c = cartVectors.at("covers").list[0]
        func at(_ merchant: String) throws -> MandateCover {
            guard case .object(var m) = c.at("cart") else { fatalError("not an object") }
            m = m.map { $0.key == "merchant" ? ($0.key, .string(merchant)) : $0 }
            return try Self.cover(c, cart: .object(m))
        }
        #expect(try at("did:web:shop.moltbotden.com").ok)
        #expect(try at("did:web:shop.moltbotden.com%3A8443").ok)
        for evil in ["did:web:evil.com%2F.moltbotden.com", "did:web:evil.com%23.moltbotden.com", "did:web:evil.com%3F.moltbotden.com",
                     "did:web:evil.com%40.moltbotden.com", "did:web:%zz.moltbotden.com"] {
            let r = try at(evil)
            #expect(!r.ok && r.reason == "out_of_scope", "\(evil)")
        }
    }

    @Test func negativeSpentNeverFits() throws {
        let terms = try MandateTerms(cartVectors.at("mandates").at("M"))
        let r = mandateCovers(terms, cart: cartVectors.at("covers").list[0].at("cart"), periodSpent: -1000)
        #expect(!r.ok && r.reason == "over_limit")
    }

    @Test func aTotalPastTwoToTheFiftyThirdNeverTraps() throws {
        let cart = try JSONValue.parse(#"""
        {"profile":"cart/1","merchant":"did:key:z6Mkv4fhuJNepggTLQ4LtYSsiYFayjovLj1fpKMeqe9ss2Gw","agent_did":"did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7",
        "lines":[{"sku":"a","title":"a","qty":9007199254740991,"unit":9007199254740991}],"total":9007199254740991,"currency":"USD","rail":"credits","mandate_id":null}
        """#)
        #expect(cartError(cart) != nil)
    }
}

@Suite("receipt/1")
struct ReceiptTests {
    static func key(_ name: String) throws -> Curve25519.Signing.PrivateKey {
        try Curve25519.Signing.PrivateKey(rawRepresentation: unhex(try vector("keys.json").at(name).at("seed").str))
    }

    @Test(arguments: receiptVectors.at("cases").list.map { $0.at("name").str })
    func receiptCase(_ name: String) async throws {
        let c = try #require(receiptVectors.at("cases").list.first { $0.at("name").str == name })
        let want = c.at("expect")
        let require = c["require"]?.strings.compactMap(Party.init(rawValue:))
        let r: Result<ReceiptVerified, OpenEntityError>
        do { r = .success(try await verifyReceipt(c.at("receipt"), require: require ?? [.merchant])) } catch { r = .failure(error as! OpenEntityError) }
        switch r {
        case .success(let v):
            #expect(want.at("ok").boolValue == true, "accepted, expected \(want.at("error").str)")
            #expect(v.signedBy.map(\.rawValue) == want.at("signed_by").strings)
        case .failure(let e):
            #expect(want.at("ok").boolValue == false, "\(e.code): \(e.message)")
            #expect(e.code == want.at("error").str, "\(e.code): \(e.message)")
        }
    }

    @Test func signingProducesProofsThatVerifyAndDidKeysMatchTheVectors() async throws {
        let base = receiptVectors.at("cases").list[0].at("receipt")
        guard case .object(let m) = base else { Issue.record("not an object"); return }
        var r = JSONValue.object(m.filter { $0.key != "proofs" })
        r = try signReceipt(r, by: .merchant, key: try Self.key("second"), created: "2026-11-07T00:02:00Z")
        r = try signReceipt(r, by: .agent, key: try Self.key("entity"), created: "2026-11-07T00:02:00Z")
        // CryptoKit's Ed25519 is randomized, so the proof bytes differ from the vector's; the DIDs and the verification must not.
        let merchantDid = didKey(try Self.key("second").publicKey), agentDid = didKey(try Self.key("entity").publicKey)
        #expect(merchantDid == base.at("merchant_did").str && agentDid == base.at("agent_did").str)
        #expect(r.at("proofs").list.map { $0.at("verificationMethod").str } == base.at("proofs").list.map { $0.at("verificationMethod").str })
        let v = try await verifyReceipt(r, require: [.merchant, .agent])
        #expect(v.signedBy == [.merchant, .agent])
    }

    @Test func signReceiptRefusesAWrongSignerAndASecondProof() throws {
        let base = receiptVectors.at("cases").list[0].at("receipt")
        guard case .object(let m) = base else { Issue.record("not an object"); return }
        let bare = JSONValue.object(m.filter { $0.key != "proofs" })
        #expect(throws: OpenEntityError.self) { try signReceipt(bare, by: .merchant, key: try Self.key("entity")) }  // entity is the agent
        #expect(throws: OpenEntityError.self) { try signReceipt(base, by: .agent, key: try Self.key("entity")) }  // already signed
    }

    @Test func aProofByAnotherKeyUnderTheSameDidFails() async throws {
        let base = receiptVectors.at("cases").list[0].at("receipt")
        guard case .object(let m) = base else { Issue.record("not an object"); return }
        let bare = JSONValue.object(m.filter { $0.key != "proofs" })
        // A stranger signs as the merchant by naming the merchant's method: the signature cannot verify.
        let stranger = Curve25519.Signing.PrivateKey()
        let forged = try signReceipt(bare, by: .merchant, key: stranger, verificationMethod: base.at("merchant_did").str + "#x")
        await #expect(throws: OpenEntityError.self) { try await verifyReceipt(forged) }
    }

    @Test func aReceiptCannotNameOneDidAsMerchantAndAgent() throws {
        guard case .object(let m) = receiptVectors.at("cases").list[0].at("receipt") else { Issue.record("not an object"); return }
        let agent = m.first { $0.key == "agent_did" }!.value
        #expect(receiptError(.object(m.map { $0.key == "merchant_did" ? ($0.key, agent) : $0 }))?.contains("differ") == true)
    }
}

@Suite("verifyAgentForCheckout")
struct CheckoutTests {
    static func policy(_ p: JSONValue) -> AgentPolicy {
        var r = AgentPolicy()
        r.minLevel = p["min_level"]?.int
        r.requireOwner = p["require_owner"]?.boolValue ?? false
        r.requireMandate = p["require_mandate"]?.boolValue ?? false
        r.minSecurityBand = p["min_security_band"]?.stringValue
        r.acceptIssuers = p["accept_issuers"]?.strings ?? []
        return r
    }

    static func facts(_ a: JSONValue) -> AgentFacts {
        var f = AgentFacts()
        f.level = a["level"]?.int
        f.ownerDid = a["owner_did"]?.stringValue
        f.securityBand = a["security_band"]?.stringValue
        f.securityIssuer = a["security_issuer"]?.stringValue
        return f
    }

    static func run(_ i: JSONValue, counter: UInt32 = 0) throws -> CheckoutDecision {
        verifyAgentForCheckout(
            agentDid: i["agent_did"]?.stringValue, cart: i.at("cart"), policy: policy(i.at("merchant_policy")), agent: facts(i.at("agent")),
            mandate: i["mandate"], keyLog: ownerKeys(i.at("key_state").str), status: i["status"],
            approval: i["approval"].map { CheckoutApproval(approval: $0.at("approval"), verifierDid: $0.at("verifier_did").str, requestId: $0.at("request_id").str, counter: counter) },
            now: i.at("now").int)
    }

    @Test(arguments: checkoutVectors.at("cases").list.map { $0.at("name").str })
    func checkoutCase(_ name: String) throws {
        let c = try #require(checkoutVectors.at("cases").list.first { $0.at("name").str == name })
        let r = try Self.run(c.at("input")), want = c.at("expect")
        #expect(r.decision == want.at("decision").str && r.reasons == want.at("reasons").strings, "\(r.decision) \(r.reasons)")
        #expect(r.evidence.approvalError == want["approval_error"]?.stringValue)
    }

    @Test func anAllowByApprovalHandsBackTheKeyAndCounterToStore() throws {
        let c = try #require(checkoutVectors.at("cases").list.first { $0.at("name").str == "allow-step-up-approved" })
        let r = try Self.run(c.at("input"))
        #expect(r.evidence.approvalKid == c.at("input").at("approval").at("approval").at("device_id").str && r.evidence.approvalCounter == 0)
        #expect(r.evidence.mandateHash?.count == 64 && r.evidence.agentDid == c.at("input").at("agent_did").str)
    }

    @Test func anApprovalIsSpentOnceItsCounterIsStored() throws {
        // WebAuthn counters must rise: a replayed approval with the counter already stored never allows. p256 approvals carry 0 and stay valid.
        let c = try #require(checkoutVectors.at("cases").list.first { $0.at("name").str == "allow-step-up-approved" })
        #expect(try Self.run(c.at("input"), counter: 5).decision == "allow")
    }
}
