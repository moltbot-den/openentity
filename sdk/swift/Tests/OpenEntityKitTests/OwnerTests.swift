import CryptoKit
import Foundation
import OpenEntityKit
import Testing

// test-vectors/keylog-1 and test-vectors/approval-2.0, checked as sdk/ts/test/owner.test.ts and sdk/python/tests/test_owner.py
// check them. Every rule has a vector; removing its guard turns that vector's result into a mismatch.

struct StoredKeys: OwnerKeys {
    let did: String
    let root: Credential
    let approvers: [Credential]
    let closed: Bool
}

func stateJSON(_ s: KeyLogState) -> JSONValue {
    .object([
        ("did", .string(s.did)), ("seq", .number(Double(s.seq))), ("head", .string(s.head)), ("root", .string(s.root.kid)),
        ("approvers", .array(s.approvers.map { .string($0.kid) })),
        ("revoked", .array(s.revoked.map { .object([("kid", .string($0.kid)), ("at", .number(Double($0.at)))]) })),
        ("pending", .array(s.pending.map {
            .object([("seq", .number(Double($0.seq))), ("op", .string($0.op)), ("hash", .string($0.hash)),
                     ("effective_at", .number(Double($0.effectiveAt)))])
        })),
        ("closed", .bool(s.closed)),
    ])
}

func runKeyLog(_ v: JSONValue, lines: [String]? = nil, firstSeenAt: [Int64]? = nil, now: Int64? = nil) -> Result<KeyLogState, OpenEntityError> {
    outcome { () throws(OpenEntityError) in
        try verifyKeyLog(did: v.at("did").str, lines: lines ?? v.at("log").strings, firstSeenAt: firstSeenAt ?? v.at("first_seen_at").list.map(\.int),
                         now: now ?? v.at("now").int, serviceKeys: v.at("service_keys").list.map(\.jwk), origins: v["origins"]?.strings)
    }
}

@Suite("owner key log (keylog-1)")
struct KeyLogTests {
    @Test func everyRuleHasAVector() {
        #expect(vectorFiles("keylog-1").count >= 50)
    }

    @Test(arguments: vectorFiles("keylog-1"))
    func vector(_ file: String) throws {
        let v = try OpenEntityKitTests.vector("keylog-1/\(file)"), want = v.at("expect")
        switch runKeyLog(v) {
        case .success(let state):
            let got = try canonicalize(stateJSON(state))
            #expect(want.at("ok").boolValue == true, "verified, expected \(want.at("error").str) at seq \(want.at("seq").int)")
            #expect(try sameJSON(stateJSON(state), want.at("state")), "\(got)")
        case .failure(let e):
            #expect(want.at("ok").boolValue == false, "\(e.code) at seq \(e.seq ?? 0): \(e.message)")
            #expect(e.code == want.at("error").str && e.seq.map(Int64.init) == want.at("seq").int, "\(e.code) at seq \(e.seq ?? 0): \(e.message)")
        }
    }

    @Test func didIsBase32OfTheGenesisLine() throws {
        let v = try OpenEntityKitTests.vector("keylog-1/genesis-device.json")
        let digest = SHA256.hash(data: Data(v.at("log").strings[0].utf8))
        var bits = digest.map { b in let s = String(b, radix: 2); return String(repeating: "0", count: 8 - s.count) + s }.joined()
        var suffix = ""
        while !bits.isEmpty {
            let chunk = String(bits.prefix(5)).padding(toLength: 5, withPad: "0", startingAt: 0)
            suffix.append(Array("abcdefghijklmnopqrstuvwxyz234567")[Int(chunk, radix: 2)!])
            bits = String(bits.dropFirst(5))
        }
        #expect(v.at("did").str == "did:web:account.openentity.org:o:\(suffix)")
    }

    @Test func badInputIsInputNotALogFailure() throws {
        let v = try OpenEntityKitTests.vector("keylog-1/genesis-device.json")
        if case .failure(let e) = runKeyLog(v, firstSeenAt: []) { #expect(e.code == "bad_first_seen" && e.seq == 1) } else { Issue.record("accepted") }
        if case .failure(let e) = runKeyLog(v, now: v.at("first_seen_at").list[0].int - 1) { #expect(e.code == "bad_first_seen") } else { Issue.record("accepted") }
        let bad = outcome { () throws(OpenEntityError) in
            try verifyKeyLog(did: v.at("did").str, lines: v.at("log").strings, firstSeenAt: v.at("first_seen_at").list.map(\.int),
                             now: v.at("now").int, serviceKeys: [JWK(x: "AA", y: "AA")])
        }
        if case .failure(let e) = bad { #expect(e.code == "invalid_input" && e.seq == nil) } else { Issue.record("accepted a bad service key") }
    }

    @Test func aBooleanIsNotTheInteger1() throws {
        let v = try OpenEntityKitTests.vector("keylog-1/genesis-device.json")
        guard case .object(let members) = try JSONValue.parse(v.at("log").strings[0]) else { Issue.record("not an object"); return }
        let line = try canonicalize(.object(members.map { m -> (key: String, value: JSONValue) in m.key == "v" ? (key: "v", value: .bool(true)) : m }))
        if case .failure(let e) = runKeyLog(v, lines: [line]) { #expect(e.code == "malformed" && e.seq == 1) } else { Issue.record("accepted v: true") }
    }

    /// Swift's String == treats the Kelvin sign U+212A as "K"; an auth.kid spelled with it must not find the root passkey.
    @Test func kidsCompareByteForByte() throws {
        let v = try OpenEntityKitTests.vector("keylog-1/add-approver-root-only.json")
        var lines = v.at("log").strings
        let kid = "\"kid\":\"07PAo82hd2JrvWLKn1nsgQpzIWE27VR0vNUbngCBKjE\""
        #expect(lines[1].contains(kid))
        lines[1] = lines[1].replacingOccurrences(of: kid, with: kid.replacingOccurrences(of: "K", with: "\u{212A}"))
        if case .success = runKeyLog(v) {} else { Issue.record("vector failed") }
        if case .failure(let e) = runKeyLog(v, lines: lines) { #expect(e.code == "unauthorized" && e.seq == 2) } else { Issue.record("accepted a look-alike kid") }
    }

    /// A P-256 x coordinate above the field prime that reduces to a point on the curve (x = 5 + p) is not a key.
    @Test func coordinatesMustBeBelowThePrime() {
        let y = b64url(unhex("459243b9aa581806fe913bce99817ade11ca503c64d9a3c533415c083248fbcc"))
        let ok = JWK(x: b64url(unhex("0000000000000000000000000000000000000000000000000000000000000005")), y: y)
        let alias = JWK(x: b64url(unhex("ffffffff00000001000000000000000000000001000000000000000000000004")), y: y)
        let run = { (key: JWK) in
            outcome { () throws(OpenEntityError) in try verifyKeyLog(did: "did:x:y", lines: ["{}"], firstSeenAt: [0], now: 0, serviceKeys: [key]) }
        }
        if case .failure(let e) = run(ok) { #expect(e.code == "malformed") }  // the key is fine; the log is not
        if case .failure(let e) = run(alias) { #expect(e.code == "invalid_input") } else { Issue.record("accepted x >= p") }
    }
}

let approvalVectors = (try? vector("approval-2.0/vectors.json")) ?? .null

@Suite("approval/2.0")
struct ApprovalTests {
    var A: JSONValue { approvalVectors }

    static func keys(_ name: String) throws -> StoredKeys {
        let s = approvalVectors.at("key_states").at(name)
        return StoredKeys(did: s.at("did").str, root: try Credential(s.at("root")), approvers: try s.at("approvers").list.map { try Credential($0) },
                          closed: s.at("closed").boolValue ?? true)
    }

    static func approve(_ c: JSONValue, keys: StoredKeys? = nil, approval: JSONValue? = nil) throws -> Result<(kid: String, counter: UInt32), OpenEntityError> {
        let x = c.at("context")
        let keys = try keys ?? Self.keys(x.at("key_state").str)
        return outcome { () throws(OpenEntityError) in
            try verifyApproval(approval ?? c.at("approval"), keyLog: keys, verifierDid: x.at("verifier_did").str, ownerDid: x.at("owner_did").str,
                               requestId: x.at("request_id").str, payloadDigest: x.at("payload_digest").str, now: x.at("now").int,
                               decisions: x["decisions"]?.strings ?? ["approve", "deny"], origins: x["origins"]?.strings,
                               counter: UInt32(x["counter"]?.int ?? 0), allowRoot: x["allow_root"]?.boolValue ?? false)
        }
    }

    @Test func digestsForBothDecisions() throws {
        #expect(A.at("digests").list.map { $0.at("fields").at("decision").str } == ["approve", "deny"])
        for d in A.at("digests").list {
            let f = d.at("fields")
            let args = (f.at("verifier_did").str, f.at("owner_did").str, f.at("request_id").str, f.at("payload_digest").str, f.at("decision").str, f.at("expires_at").int)
            #expect(try approvalPreimage(verifierDid: args.0, ownerDid: args.1, requestId: args.2, payloadDigest: args.3, decision: args.4, expiresAt: args.5) == d.at("preimage").str)
            #expect(hex(SHA256.hash(data: Data(d.at("preimage").str.utf8))) == d.at("digest").str)
            #expect(hex(try approvalDigest(verifierDid: args.0, ownerDid: args.1, requestId: args.2, payloadDigest: args.3, decision: args.4, expiresAt: args.5)) == d.at("digest").str)
            for bad in [(args.0, args.1, "a|b", args.3, args.4, args.5), (args.0, args.1, "a\n", args.3, args.4, args.5),
                        (args.0, "did:web:x|y", args.2, args.3, args.4, args.5), (args.0, args.1, args.2, String(repeating: "AB", count: 32), args.4, args.5),
                        (args.0, args.1, args.2, args.3, "maybe", args.5), (args.0, args.1, args.2, args.3, args.4, -1),
                        ("did:web:", args.1, args.2, args.3, args.4, args.5), (args.0, args.1, String(repeating: "a", count: 129), args.3, args.4, args.5)] {
                #expect(throws: OpenEntityError.self) {
                    try approvalDigest(verifierDid: bad.0, ownerDid: bad.1, requestId: bad.2, payloadDigest: bad.3, decision: bad.4, expiresAt: bad.5)
                }
            }
        }
    }

    @Test func payloadDigestsAreSHA256OfJCS() throws {
        #expect(A.at("payloads").list.count >= 4)
        for p in A.at("payloads").list {
            #expect(try canonicalize(p.at("summary")) == p.at("canonical").str)
            #expect(try payloadDigest(p.at("summary")) == p.at("digest").str)
        }
        #expect(!A.at("payloads_invalid").list.isEmpty)
        for p in A.at("payloads_invalid").list {
            #expect(throws: OpenEntityError.self, "\(p.at("reason").str)") { try payloadDigest(p.at("summary")) }
        }
    }

    @Test(arguments: approvalVectors.at("cases").list.map { $0.at("name").str })
    func approvalCase(_ name: String) throws {
        let c = try #require(A.at("cases").list.first { $0.at("name").str == name })
        let want = c.at("expect")
        switch try Self.approve(c) {
        case .success(let r):
            #expect(want.at("ok").boolValue == true, "accepted, expected \(want.at("error").str)")
            #expect(r.kid == want.at("kid").str && Int64(r.counter) == want.at("counter").int)
        case .failure(let e):
            #expect(want.at("ok").boolValue == false, "\(e.code): \(e.message)")
            #expect(e.code == want.at("error").str, "\(e.code): \(e.message)")
        }
    }

    @Test func keyStatesComeFromTheirLogs() throws {
        let service = try vector("approval-2.0/keys.json").at("keys").at("service").at("jwk").jwk
        let ctx = A.at("cases").list[0].at("context")
        guard case .object(let logs) = A.at("key_logs") else { Issue.record("no key_logs"); return }
        #expect(logs.count == 4 && logs.count == (A.at("key_states").objectCount))
        for (name, l) in logs {
            let state = try verifyKeyLog(did: l.at("did").str, lines: l.at("log").strings, firstSeenAt: l.at("first_seen_at").list.map(\.int),
                                         now: ctx.at("now").int, serviceKeys: [service], origins: ctx.at("origins").strings)
            let want = A.at("key_states").at(name)
            #expect(state.did == want.at("did").str && state.closed == want.at("closed").boolValue, "\(name)")
            #expect(try sameJSON(state.root.json, want.at("root")), "\(name)")
            #expect(try sameJSON(.array(state.approvers.map(\.json)), want.at("approvers")), "\(name)")
        }
    }

    /// Numbers are JavaScript doubles: 1794017100.0 is the integer 1794017100 in expires_at (and the preimage prints it
    /// without a decimal point) and in a payload summary.
    @Test func integralDoublesAreIntegers() throws {
        let c = try #require(A.at("cases").list.first { $0.at("name").str == "p256-approve" })
        let exp = String(c.at("approval").at("expires_at").int)
        let text = try canonicalize(c.at("approval")).replacingOccurrences(of: "\"expires_at\":\(exp)", with: "\"expires_at\":\(exp).0")
        #expect(text.contains("\(exp).0"))
        if case .success(let r) = try Self.approve(c, approval: JSONValue.parse(text)) { #expect(r.kid == c.at("expect").at("kid").str) } else { Issue.record("rejected \(exp).0") }
        #expect(try payloadDigest(JSONValue.parse(#"{"a":125000.0,"b":[1e2]}"#)) == payloadDigest(JSONValue.parse(#"{"a":125000,"b":[100]}"#)))
    }

    /// The single-credential root kid has a "K"; a device_id spelled with the Kelvin sign is a different key.
    @Test func deviceIdComparesByteForByte() throws {
        let c = try #require(A.at("cases").list.first { $0.at("name").str == "root-single-credential" })
        guard case .object(let members) = c.at("approval") else { Issue.record("no approval"); return }
        #expect(c.at("approval").at("device_id").str.contains("K"))
        let lookalike = JSONValue.object(members.map { m -> (key: String, value: JSONValue) in
            m.key == "device_id" ? (key: "device_id", value: .string(m.value.str.replacingOccurrences(of: "K", with: "\u{212A}"))) : m
        })
        if case .success(let r) = try Self.approve(c) { #expect(r.kid == "07PAo82hd2JrvWLKn1nsgQpzIWE27VR0vNUbngCBKjE") } else { Issue.record("vector failed") }
        if case .failure(let e) = try Self.approve(c, approval: lookalike) { #expect(e.code == "unknown_key") } else { Issue.record("accepted a look-alike device_id") }
    }
}
