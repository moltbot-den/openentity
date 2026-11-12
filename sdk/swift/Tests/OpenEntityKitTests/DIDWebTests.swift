import Foundation
import OpenEntityKit
import Testing

// test-vectors/did-web-1 through an injected fetch (no network), and the cache rules: keys kept ten minutes per DID, a refetch
// when a proof names a method the cached keys lack, at most one fetch every thirty seconds per DID.

let didWebVectors = (try? vector("did-web-1/vectors.json")) ?? .null
let issuerURL = "https://issuer.example/.well-known/did.json"
let issuer = "did:web:issuer.example"

func didWebCase(_ name: String) throws -> JSONValue {
    try #require(didWebVectors.at("cases").list.first { $0.at("name").str == name })
}

/// A fake web and clock: serves documents by URL, records every fetch, and fails for any URL it does not serve.
final class FakeWeb: @unchecked Sendable {
    private let lock = NSLock()
    private var documents: [String: JSONValue]
    private var log: [String] = []
    private var clock: TimeInterval = 0
    private let delay: Duration

    init(_ documents: [String: JSONValue], delay: Duration = .zero) {
        self.documents = documents
        self.delay = delay
    }

    var fetched: [String] { lock.withLock { log } }
    func serve(_ url: String, _ document: JSONValue) { lock.withLock { documents[url] = document } }
    func advance(to t: TimeInterval) { lock.withLock { clock = t } }

    func resolver() -> DIDWebResolver {
        DIDWebResolver(fetch: { url in try await self.get(url) }, now: { self.lock.withLock { self.clock } })
    }

    private func get(_ url: URL) async throws -> JSONValue {
        if delay > .zero { try await Task.sleep(for: delay) }
        return try lock.withLock {
            log.append(url.absoluteString)
            guard let document = documents[url.absoluteString] else { throw URLError(.fileDoesNotExist) }
            return document
        }
    }
}

/// `attestation` with its proof naming `method`.
func naming(_ method: String, _ attestation: JSONValue) -> JSONValue {
    guard case .object(let members) = attestation, case .object(let proof)? = attestation["proof"] else { return attestation }
    let renamed = JSONValue.object(proof.map { m -> (key: String, value: JSONValue) in
        m.key == "verificationMethod" ? (key: m.key, value: .string(method)) : m
    })
    return .object(members.map { m -> (key: String, value: JSONValue) in m.key == "proof" ? (key: m.key, value: renamed) : m })
}

/// `document` after the issuer adds key-3 (the `unlisted` key of did-web-1/keys.json) as a JsonWebKey method.
func addingKey3(_ document: JSONValue) throws -> JSONValue {
    let x = b64url(unhex(try vector("did-web-1/keys.json").at("unlisted").at("publicKeyHex").str))
    let method = try JSONValue.parse(##"{"id":"#key-3","type":"JsonWebKey","controller":"did:web:issuer.example","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"\##(x)"}}"##)
    guard case .object(let members) = document else { return document }
    return .object(members.map { m -> (key: String, value: JSONValue) in
        m.key == "verificationMethod" ? (key: m.key, value: .array(m.value.list + [method])) : m
    })
}

func failure(_ object: JSONValue, _ resolver: DIDWebResolver) async -> OpenEntityError? {
    do throws(OpenEntityError) {
        _ = try await verifyObject(object, resolver: resolver)
        return nil
    } catch {
        return error
    }
}

@Suite("did:web issuers (did-web-1)")
struct DIDWebTests {
    @Test func everyCaseIsHere() {
        #expect(didWebVectors.at("cases").list.count >= 7)
    }

    /// Each case: a fetch that serves `document` at `url` and fails elsewhere, one fetch of `url`, and `expect`.
    @Test(arguments: didWebVectors.at("cases").list.map { $0.at("name").str })
    func vectorCase(_ name: String) async throws {
        let c = try didWebCase(name), want = c.at("expect")
        let web = FakeWeb([c.at("url").str: c.at("document")])
        let signer = try? await verifyObject(c.at("attestation"), resolver: web.resolver())
        #expect(signer == (want.at("ok").boolValue == true ? want.at("signer").str : nil))
        #expect(web.fetched == [c.at("url").str])
    }

    @Test func keysAreCachedForTenMinutes() async throws {
        let key1 = try didWebCase("multikey-absolute-id"), key2 = try didWebCase("jsonwebkey-relative-id")
        let web = FakeWeb([issuerURL: key1.at("document")]), resolver = web.resolver()
        #expect(try await verifyObject(key1.at("attestation"), resolver: resolver) == issuer)
        web.advance(to: 599)
        #expect(try await verifyObject(key2.at("attestation"), resolver: resolver) == issuer)
        #expect(web.fetched.count == 1)
        web.advance(to: 600)
        #expect(try await verifyObject(key1.at("attestation"), resolver: resolver) == issuer)
        #expect(web.fetched.count == 2)
    }

    /// A key rotation: a proof naming key-3, which the cached document lacks, refetches once 30 seconds have passed.
    @Test func anUnknownMethodRefetches() async throws {
        let known = try didWebCase("multikey-absolute-id"), rotated = try didWebCase("unlisted-key")
        let web = FakeWeb([issuerURL: known.at("document")]), resolver = web.resolver()
        _ = try await verifyObject(known.at("attestation"), resolver: resolver)
        web.serve(issuerURL, try addingKey3(known.at("document")))
        web.advance(to: 29)
        #expect(await failure(rotated.at("attestation"), resolver)?.code == "verification_failed")
        #expect(web.fetched.count == 1)
        web.advance(to: 30)
        #expect(try await verifyObject(rotated.at("attestation"), resolver: resolver) == issuer)
        #expect(web.fetched.count == 2)
        web.advance(to: 45)
        #expect(try await verifyObject(rotated.at("attestation"), resolver: resolver) == issuer)
        #expect(web.fetched.count == 2)
    }

    /// The floor counts from the last fetch: bad proofs naming an unknown method fetch at most once every 30 seconds.
    @Test func thirtySecondFloor() async throws {
        let known = try didWebCase("multikey-absolute-id"), unlisted = try didWebCase("unlisted-key")
        let web = FakeWeb([issuerURL: known.at("document")]), resolver = web.resolver()
        _ = try await verifyObject(known.at("attestation"), resolver: resolver)
        for (t, fetches) in [(1.0, 1), (29, 1), (31, 2), (45, 2), (60, 2), (61, 3), (90, 3), (91, 4), (120, 4)] {
            web.advance(to: t)
            #expect(await failure(unlisted.at("attestation"), resolver) != nil)
            #expect(web.fetched.count == fetches, "at \(t) seconds")
        }
    }

    @Test func concurrentLookupsShareOneFetch() async throws {
        let c = try didWebCase("multikey-absolute-id")
        let web = FakeWeb([issuerURL: c.at("document")], delay: .milliseconds(100)), resolver = web.resolver()
        let attestation = c.at("attestation")
        let signers = await withTaskGroup(of: String?.self) { group in
            for _ in 0..<8 { group.addTask { try? await verifyObject(attestation, resolver: resolver) } }
            return await group.reduce(into: [String?]()) { $0.append($1) }
        }
        #expect(signers == Array(repeating: issuer, count: 8))
        #expect(web.fetched.count == 1)
    }

    /// A failed fetch is `unresolvable` and not cached; a document naming another DID is `verification_failed`, also uncached.
    @Test func failuresAreNotCached() async throws {
        let c = try didWebCase("multikey-absolute-id"), other = try didWebCase("document-names-another-did")
        let web = FakeWeb([:]), resolver = web.resolver()
        #expect(await failure(c.at("attestation"), resolver)?.code == "unresolvable")
        web.serve(issuerURL, other.at("document"))
        #expect(await failure(c.at("attestation"), resolver)?.code == "verification_failed")
        web.serve(issuerURL, c.at("document"))
        #expect(try await verifyObject(c.at("attestation"), resolver: resolver) == issuer)
        #expect(web.fetched.count == 3)
    }

    @Test func didKeyStaysOffline() async throws {
        let web = FakeWeb([:])
        #expect(try await verifyObject(vector("declaration.json").at("object"), resolver: web.resolver()) == entity)
        #expect(web.fetched.isEmpty)
    }

    @Test func offlineVerificationNeedsTheResolver() throws {
        let c = try didWebCase("multikey-absolute-id")
        if case .failure(let e) = outcome({ () throws(OpenEntityError) in try verifyObject(c.at("attestation")) }) {
            #expect(e.code == "unsupported")
        } else {
            Issue.record("verified a did:web proof without a resolver")
        }
    }

    /// did-web-1 step 1. A DID whose decoded parts are not a plain host and path segments is refused without a fetch.
    @Test(arguments: [
        ("did:web:issuer.example", "https://issuer.example/.well-known/did.json"),
        ("did:web:issuer.example%3A8443:teams:red", "https://issuer.example:8443/teams/red/did.json"),
        ("did:web:issuer.example:user:alice%40home", "https://issuer.example/user/alice@home/did.json"),
        ("did:web:", nil), ("did:web:issuer.example:", nil), ("did:web:evil.example%2Fx", nil), ("did:web:issuer.example%3F", nil),
        ("did:web:issuer.example:..:x", nil), ("did:web:issuer.example%3A99999", nil), ("did:web:issuer.example:%zz", nil),
        ("did:web:issuer.example:a%20b", nil), ("did:web:issuer.example:a%25b", nil), ("did:web:issu\u{e9}r.example", nil),
    ] as [(String, String?)])
    func documentURL(_ did: String, _ url: String?) async throws {
        let web = FakeWeb([:])
        let attestation = naming("\(did)#key-1", try didWebCase("multikey-absolute-id").at("attestation"))
        #expect(await failure(attestation, web.resolver())?.code == "unresolvable")
        #expect(web.fetched == (url.map { [$0] } ?? []))
    }
}
