import Foundation

// did:web issuers (test-vectors/did-web-1/README.md): the did.json URL, the Ed25519 keys a document yields, and the per-DID
// cache. A port of didWebUrl (sdk/ts/src/core.ts), ed25519Methods and the didWebKeys cache rules (sdk/ts/src/httpsig.ts).

/// Resolves did:web DIDs to their Ed25519 keys through `https://<host>/.well-known/did.json`, or `<path>/did.json` for a DID
/// with a path. A document's keys stay cached for ten minutes per DID; a proof that names a method the cached keys lack
/// refetches the document, at most once every thirty seconds per DID, so a key rotation shows up without letting a stream of
/// bad proofs become a stream of fetches. Concurrent lookups of one DID share one fetch.
public actor DIDWebResolver {
    /// Fetches the DID document at `url` and returns it as JSON. Inject one for tests or to use your own HTTP client.
    public typealias Fetch = @Sendable (URL) async throws -> JSONValue
    typealias Keys = [(id: String, key: [UInt8])]

    private let fetch: Fetch
    private let now: @Sendable () -> TimeInterval
    private var cache: [String: (at: TimeInterval, keys: Keys)] = [:]
    private var inflight: [String: Task<Keys, any Error>] = [:]

    /// `now` is seconds on a monotonic clock; the default one keeps counting while the device sleeps.
    public init(fetch: @escaping Fetch = DIDWebResolver.https,
                now: @escaping @Sendable () -> TimeInterval = { Double(clock_gettime_nsec_np(CLOCK_MONOTONIC)) / 1e9 }) {
        self.fetch = fetch
        self.now = now
    }

    /// The Ed25519 keys of the DID document of `method` (`did:web:...#fragment`), by absolute method id.
    func keys(for method: String) async throws(OpenEntityError) -> Keys {
        let did = String(decoding: method.utf8.prefix { $0 != UInt8(ascii: "#") }, as: UTF8.self)
        let url = try didWebURL(did)  // also limits `did` to ASCII, so the String-keyed maps compare bytes
        if let hit = cache[did] {
            let age = now() - hit.at
            if age < 600 && (age < 30 || hit.keys.contains { same($0.id, method) }) { return hit.keys }
        }
        let task = inflight[did] ?? Task { [fetch] in
            let document = try await fetch(url)
            return try ed25519Methods(did, document)
        }
        inflight[did] = task
        let result = await task.result
        if inflight[did] == task { inflight[did] = nil }
        switch result {
        case .success(let keys):
            cache[did] = (now(), keys)
            return keys
        case .failure(let error as OpenEntityError):
            throw error
        case .failure(let error):
            throw OpenEntityError("unresolvable", "\(url.absoluteString): \(error.localizedDescription)")
        }
    }
}

extension DIDWebResolver {
    /// The default fetch: an HTTPS GET with no redirects, cookies or HTTP cache, a 5 second timeout and a 256 KiB cap.
    /// Anything but a 200 with a JSON body throws `unresolvable`.
    public static let https: Fetch = { url in
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 5)
        request.setValue("application/did+json, application/json", forHTTPHeaderField: "Accept")
        let (bytes, response) = try await session.bytes(for: request, delegate: NoRedirects())
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard status == 200 else { throw OpenEntityError("unresolvable", "\(url.absoluteString) answered \(status)") }
        var body = Data()
        for try await byte in bytes {
            body.append(byte)
            if body.count > 262_144 { throw OpenEntityError("unresolvable", "\(url.absoluteString) is larger than 256 KiB") }
        }
        do throws(OpenEntityError) {
            return try JSONValue.parse(body)
        } catch {
            throw OpenEntityError("unresolvable", "\(url.absoluteString): \(error.message)")
        }
    }

    private static let session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        configuration.httpShouldSetCookies = false
        configuration.timeoutIntervalForResource = 10
        return URLSession(configuration: configuration)
    }()
}

/// did.json is served where the DID says, never somewhere a redirect points.
final class NoRedirects: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest) async -> URLRequest? { nil }
}

/// did-web-1 step 1: drop `did:web:`, split the rest on `:` and percent-decode each part. The first part is the host (a port
/// written as `%3A`); the rest is the path, else `.well-known`. A part that is not a plain host or path segment once decoded
/// (a `/`, `?`, `#`, `%`, space, dot segment or non-ASCII byte) is refused rather than fetched.
func didWebURL(_ did: String) throws(OpenEntityError) -> URL {
    let refuse = OpenEntityError("unresolvable", "\(did) is not a did:web DID with a host this resolver fetches")
    let prefix = Array("did:web:".utf8), b = Array(did.utf8)
    guard b.starts(with: prefix) else { throw refuse }
    var parts: [String] = []
    for raw in b[prefix.count...].split(separator: UInt8(ascii: ":"), omittingEmptySubsequences: false) {
        guard let part = String(decoding: raw, as: UTF8.self).removingPercentEncoding else { throw refuse }
        parts.append(part)
    }
    let host = parts[0], path = parts.dropFirst()
    guard isHost(host), path.allSatisfy(isPathSegment),
          let url = URL(string: "https://\(host)/\(path.isEmpty ? ".well-known" : path.joined(separator: "/"))/did.json")
    else { throw refuse }
    return url
}

/// A DNS name or address of letters, digits, dots and hyphens, with an optional port in 1...65535.
func isHost(_ s: String) -> Bool {
    let parts = s.utf8.split(separator: UInt8(ascii: ":"), omittingEmptySubsequences: false)
    guard (1...2).contains(parts.count), !parts[0].isEmpty,
          parts[0].allSatisfy({ isAlnum($0) || $0 == UInt8(ascii: ".") || $0 == UInt8(ascii: "-") }) else { return false }
    guard parts.count == 2 else { return true }
    let port = Int(String(decoding: parts[1], as: UTF8.self)) ?? 0
    return (1...5).contains(parts[1].count) && parts[1].allSatisfy { (0x30...0x39).contains($0) } && (1...65_535).contains(port)
}

/// An RFC 3986 path segment without percent escapes: unreserved, sub-delims, `:` and `@`; never `.` or `..`.
func isPathSegment(_ s: String) -> Bool {
    let allowed = Array("-._~!$&'()*+,;=:@".utf8)
    return !s.isEmpty && !same(s, ".") && !same(s, "..") && s.utf8.allSatisfy { isAlnum($0) || allowed.contains($0) }
}

/// did-web-1 steps 2 and 3: the document must name exactly `did`; its Ed25519 keys by absolute method id (`#key-1` is
/// relative to the DID). A `publicKeyMultibase` Ed25519 multikey or an OKP Ed25519 `publicKeyJwk` with strict base64url `x`;
/// the method `type` does not decide, and any other key yields nothing. A repeated id keeps its last key, as in TS.
func ed25519Methods(_ did: String, _ document: JSONValue) throws(OpenEntityError) -> DIDWebResolver.Keys {
    guard let id = document["id"]?.stringValue, same(id, did) else {
        throw OpenEntityError("verification_failed", "the document at \(did)'s URL names another DID")
    }
    var keys: DIDWebResolver.Keys = []
    for method in document["verificationMethod"]?.arrayValue ?? [] {
        guard let ref = method["id"]?.stringValue else { continue }
        let id = ref.utf8.first == UInt8(ascii: "#") ? did + ref : ref
        var key: [UInt8]?
        if let multibase = method["publicKeyMultibase"]?.stringValue {
            key = try? didKeyPublicKey("did:key:" + multibase)
        } else if let jwk = method["publicKeyJwk"], same(jwk["kty"]?.stringValue ?? "", "OKP"), same(jwk["crv"]?.stringValue ?? "", "Ed25519") {
            key = b64u(jwk["x"])
        }
        guard let key, key.count == 32 else { continue }
        keys.removeAll { same($0.id, id) }
        keys.append((id, key))
    }
    return keys
}
