import CryptoKit
import Foundation

// Owner key logs (keylog-1, ADR 0007) and approval/2.0 (ADR 0008), verify only. A port of sdk/ts/src/owner.ts: the same
// checks in the same order with the same error codes. test-vectors/keylog-1 and test-vectors/approval-2.0 define both.

/// The RP ID of the account service passkeys; the default `rpId` everywhere.
public let defaultRpId = "account.openentity.org"

let day: Int64 = 86_400
let week: Int64 = 7 * day
let maxTTL: Int64 = 600
let maxSafe: Int64 = 9_007_199_254_740_991  // 2^53 - 1
// The P-256 group order n and n >> 1, big-endian.
let order: [UInt8] = hexBytes("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
let halfOrder: [UInt8] = hexBytes("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8")

/// A P-256 public JWK, `{kty: "EC", crv: "P-256", x, y}` with base64url coordinates.
public struct JWK: Sendable {
    public var kty: String
    public var crv: String
    public var x: String
    public var y: String

    public init(kty: String = "EC", crv: String = "P-256", x: String, y: String) {
        self.kty = kty
        self.crv = crv
        self.x = x
        self.y = y
    }
}

/// A key in an owner key log: a device P-256 key (`p256`) or a passkey (`webauthn`).
public struct Credential: Sendable {
    /// RFC 7638 thumbprint of `jwk`: the key fingerprint the app shows.
    public let kid: String
    /// `p256` or `webauthn`.
    public let type: String
    public let jwk: JWK
    /// The credential object as the log carries it, descriptive fields (label, platform, attestation) included.
    public let json: JSONValue
}

extension Credential {
    /// A credential from its JSON (for example a stored key state), checked as the key log checks one. Throws `invalid_input`.
    public init(_ json: JSONValue, rpId: String = defaultRpId) throws(OpenEntityError) {
        do throws(OpenEntityError) {
            self = try credential(json, rpId: rpId, what: "credential")
        } catch {
            throw OpenEntityError("invalid_input", error.message)
        }
    }
}

/// What verifyApproval needs from the owner's key log: verifyKeyLog's state, or a stored copy of these four fields.
public protocol OwnerKeys {
    var did: String { get }
    var root: Credential { get }
    var approvers: [Credential] { get }
    var closed: Bool { get }
}

public struct Revocation: Sendable {
    public let kid: String
    public let at: Int64
}

public struct PendingOperation: Sendable {
    public let seq: Int
    /// `recover` or `replace_root`.
    public let op: String
    /// The entry hash a `cancel` names.
    public let hash: String
    public let effectiveAt: Int64
}

/// The verified state of an owner key log as of `now`. `approvers` are the keys that may sign approval/2.0 now, in the order
/// they took effect: the root passkey alone in a single-credential log. `revoked` is in the order revoked.
public struct KeyLogState: OwnerKeys, Sendable {
    public let did: String
    public let seq: Int
    /// SHA-256 hex of the last line: the next entry's `prev`.
    public let head: String
    public let root: Credential
    public let approvers: [Credential]
    public let revoked: [Revocation]
    public let pending: [PendingOperation]
    public let closed: Bool
}

// ---------------------------------------------------------------- approval/2.0

/// ADR 0008 preimage, `approval/2.0|verifier_did|owner_did|request_id|payload_digest|decision|expires_at`. The app signs its
/// UTF-8 bytes with CryptoKit, whose `signature(for:)` hashes them with SHA-256. Throws `invalid_input` for a field that is
/// not in its form (none can then contain `|`).
public func approvalPreimage(verifierDid: String, ownerDid: String, requestId: String, payloadDigest: String,
                             decision: String, expiresAt: Int64) throws(OpenEntityError) -> String {
    try ApprovalFields("invalid_input", verifierDid, ownerDid, requestId, payloadDigest, decision, expiresAt).preimage
}

/// SHA-256 of approvalPreimage: what a p256 signature covers, and (base64url) the WebAuthn challenge.
public func approvalDigest(verifierDid: String, ownerDid: String, requestId: String, payloadDigest: String,
                           decision: String, expiresAt: Int64) throws(OpenEntityError) -> Data {
    let preimage = try approvalPreimage(verifierDid: verifierDid, ownerDid: ownerDid, requestId: requestId,
                                        payloadDigest: payloadDigest, decision: decision, expiresAt: expiresAt)
    return Data(sha256(Array(preimage.utf8)))
}

/// Lowercase hex SHA-256 of the RFC 8785 form of the summary the owner saw; the app recomputes it from the summary it shows
/// before signing. Numbers must be integers within 2^53 - 1 (amounts in minor units or strings), else `invalid_input`.
public func payloadDigest(_ summary: JSONValue) throws(OpenEntityError) -> String {
    if let e = plainError(summary) { throw OpenEntityError("invalid_input", e) }
    let canonical = try canonicalize(summary)
    return hex(sha256(Array(canonical.utf8)))
}

/// Verifies an approval/2.0 object against the owner's verified key log and returns the signing kid and the WebAuthn counter
/// to store (0 for p256). `requestId` and `payloadDigest` are what this verifier issued and recomputes now, never the
/// client's. `origins` defaults to `https://<rpId>`; add the Android app's `android:apk-key-hash:` origin. `allowRoot` also
/// accepts the log's root passkey: off by default, only for account-service flows such as cancelling a deletion request
/// (revoked approvers never sign approvals). Throws the first failing check's code (approval-2.0/README.md); rejects
/// approval/1.0.
public func verifyApproval(_ approval: JSONValue, keyLog: some OwnerKeys, verifierDid: String, ownerDid: String,
                           requestId: String, payloadDigest: String, now: Int64, decisions: [String] = ["approve", "deny"],
                           origins: [String]? = nil, rpId: String = defaultRpId, counter stored: UInt32 = 0,
                           allowRoot: Bool = false) throws(OpenEntityError) -> (kid: String, counter: UInt32) {
    let a = approval
    guard case .object = a else { throw OpenEntityError("malformed", "approval must be an object") }
    guard let version = a["version"]?.stringValue, same(version, "approval/2.0") else {
        throw OpenEntityError("bad_version", "version is not approval/2.0")
    }
    let f = try ApprovalFields("malformed", a["verifier_did"]?.stringValue, a["owner_did"]?.stringValue, a["request_id"]?.stringValue,
                               a["payload_digest"]?.stringValue, a["decision"]?.stringValue, uint(a["expires_at"]))
    guard let deviceId = a["device_id"]?.stringValue else { throw OpenEntityError("malformed", "device_id must be a string") }
    if let shape = signedShape(a) { throw OpenEntityError("malformed", shape) }
    guard same(f.verifierDid, verifierDid) else { throw OpenEntityError("wrong_verifier", "approval is for \(f.verifierDid)") }
    guard same(f.ownerDid, ownerDid), same(f.ownerDid, keyLog.did) else { throw OpenEntityError("wrong_owner", "approval names another owner") }
    guard !keyLog.closed else { throw OpenEntityError("owner_closed", "the owner's key log is closed") }
    guard same(f.requestId, requestId) else { throw OpenEntityError("wrong_request", "the request changed; fetch a new one") }
    guard same(f.payloadDigest, payloadDigest) else { throw OpenEntityError("wrong_payload", "payload digest does not match the action") }
    guard decisions.contains(where: { same($0, f.decision) }) else {
        throw OpenEntityError("bad_decision", "decision \(f.decision) is not accepted here")
    }
    guard now < f.expiresAt else { throw OpenEntityError("expired", "approval expired") }
    guard f.expiresAt <= now + maxTTL else { throw OpenEntityError("expiry_too_far", "expires_at is more than 600 seconds away") }
    let root = allowRoot && same(keyLog.root.kid, deviceId) ? keyLog.root : nil
    guard let cred = keyLog.approvers.first(where: { same($0.kid, deviceId) }) ?? root else {
        throw OpenEntityError("unknown_key", "device_id is not a current approver in the owner's key log")
    }
    let counter = try checkSignature(cred, a, message: Array(f.preimage.utf8), origins: origins ?? ["https://\(rpId)"],
                                     rpId: rpId, lowS: false)
    if same(cred.type, "webauthn") && (counter != 0 || stored != 0) && counter <= stored {
        throw OpenEntityError("counter_replayed", "signature counter did not increase")
    }
    return (cred.kid, counter)
}

/// The six signed fields, each in its form.
struct ApprovalFields {
    let verifierDid, ownerDid, requestId, payloadDigest, decision: String
    let expiresAt: Int64

    init(_ code: String, _ verifierDid: String?, _ ownerDid: String?, _ requestId: String?, _ payloadDigest: String?,
         _ decision: String?, _ expiresAt: Int64?) throws(OpenEntityError) {
        guard let verifierDid, isDID(verifierDid) else { throw OpenEntityError(code, "verifier_did must be a DID") }
        guard let ownerDid, isDID(ownerDid) else { throw OpenEntityError(code, "owner_did must be a DID") }
        guard let requestId, (1...128).contains(requestId.utf8.count), requestId.utf8.allSatisfy(isRequestIdByte) else {
            throw OpenEntityError(code, "request_id must be 1 to 128 of [A-Za-z0-9:._-]")
        }
        guard let payloadDigest, isHex64(payloadDigest) else { throw OpenEntityError(code, "payload_digest must be 64 lowercase hex") }
        guard let decision, same(decision, "approve") || same(decision, "deny") else {
            throw OpenEntityError(code, "decision must be approve or deny")
        }
        guard let expiresAt, (0...maxSafe).contains(expiresAt) else { throw OpenEntityError(code, "expires_at must be unix seconds") }
        self.verifierDid = verifierDid
        self.ownerDid = ownerDid
        self.requestId = requestId
        self.payloadDigest = payloadDigest
        self.decision = decision
        self.expiresAt = expiresAt
    }

    var preimage: String {
        ["approval/2.0", verifierDid, ownerDid, requestId, payloadDigest, decision, String(expiresAt)].joined(separator: "|")
    }
}

// ---------------------------------------------------------------- key log

enum Op: String, CaseIterable {
    case genesis, addApprover = "add_approver", recover, replaceRoot = "replace_root", cancel, revoke, close

    var body: [String] {
        switch self {
        case .genesis: ["approver", "root"]
        case .addApprover: ["approver"]
        case .recover: ["approvers"]
        case .replaceRoot: ["root"]
        case .cancel: ["target"]
        case .revoke: ["kid"]
        case .close: []
        }
    }
}

struct Entry {
    let seq: Int64
    let prev: String?
    let op: Op
    /// genesis: the root, then the first approver if any; add_approver, recover, replace_root: the keys it introduces.
    let creds: [Credential]
    /// cancel: the target entry hash; revoke: the kid.
    let target: String
    let kid: String
    let auth: JSONValue
    /// RFC 8785 bytes of the entry without `auth`: the signature covers their SHA-256.
    let signed: [UInt8]
}

struct Pending {
    let seq: Int
    let op: Op
    let hash: String
    let effectiveAt: Int64
    let creds: [Credential]
}

/// Verifies an owner key log (one RFC 8785 entry per line) against the owner DID it must hash to, and returns its state as
/// of `now`. `firstSeenAt[i]` is when this verifier first held entry i with its whole chain (unix seconds, never decreasing):
/// every delay runs from it, never from the entry's `ts`. `serviceKeys` are the account service's close keys, which sign
/// `close`: every P-256 assertionMethod key in did:web:account.openentity.org's did.json, current and retired (never the
/// token keys in jwks.json). Throws the first failing entry's code with its `seq`, or `invalid_input` (no seq) for a bad
/// service key.
public func verifyKeyLog(did: String, lines: [String], firstSeenAt: [Int64], now: Int64, serviceKeys: [JWK] = [],
                         origins: [String]? = nil, rpId: String = defaultRpId) throws(OpenEntityError) -> KeyLogState {
    let origins = origins ?? ["https://\(rpId)"]
    var services: [Credential] = []
    for jwk in serviceKeys {
        guard p256Key(jwk) != nil else {
            throw OpenEntityError("invalid_input", "serviceKeys must be P-256 public JWKs {kty, crv, x, y}")
        }
        let kid = thumbprint(jwk)
        services.append(Credential(kid: kid, type: "p256", jwk: jwk, json: .object([("kid", .string(kid)), ("type", .string("p256"))])))
    }
    var seq = 1
    do throws(OpenEntityError) {
        guard !lines.isEmpty else { throw OpenEntityError("malformed", "a key log starts with its genesis entry") }
        guard firstSeenAt.count == lines.count else { throw OpenEntityError("bad_first_seen", "one first_seen_at per entry") }
        var root: Credential?
        var single = false, closed = false, head = ""
        var approvers: [Credential] = [], pending: [Pending] = []
        var revoked: [(cred: Credential, at: Int64)] = []
        var seen = Set<String>()  // kids are checked thumbprints (ASCII), so String equality is byte equality here
        var delayed: [String: Op] = [:]  // entry hash (lowercase hex) of each recover and replace_root

        func isRoot(_ kid: String) -> Bool { root.map { same($0.kid, kid) } ?? false }
        func approver(_ kid: String) -> Credential? { (single ? (root.map { [$0] } ?? []) : approvers).first { same($0.kid, kid) } }
        func due(_ t: Int64) {
            while let p = pending.first, p.effectiveAt <= t {
                pending.removeFirst()
                if p.op == .replaceRoot {
                    root = p.creds[0]
                } else {
                    revoked += approvers.map { ($0, p.effectiveAt) }
                    approvers = p.creds
                    single = false
                }
            }
        }
        func fresh(_ creds: [Credential]) throws(OpenEntityError) {
            for c in creds {
                guard seen.insert(c.kid).inserted else { throw OpenEntityError("key_reused", "key \(c.kid) is already in this log") }
            }
        }

        for (i, line) in lines.enumerated() {
            seq = i + 1
            let t = firstSeenAt[i]
            guard (0...maxSafe).contains(t), t <= now, i == 0 || t >= firstSeenAt[i - 1] else {
                throw OpenEntityError("bad_first_seen", "first_seen_at must be unix seconds, never decreasing, not after now")
            }
            if i > 0 { due(t) }
            let e = try parseEntry(line, rpId: rpId, first: i == 0)
            if closed { throw OpenEntityError("closed", "the log is closed") }
            guard e.seq == Int64(seq) else { throw OpenEntityError("bad_seq", "seq must be \(seq)") }
            if i == 0 {
                guard e.prev == nil else { throw OpenEntityError("bad_prev", "genesis prev must be null") }
            } else {
                guard let prev = e.prev, same(prev, head) else { throw OpenEntityError("bad_prev", "prev is not the SHA-256 of the previous entry") }
            }
            let lineHash = sha256(Array(line.utf8))
            let hash = hex(lineHash)
            var signer: Credential?
            switch e.op {
            case .genesis:
                guard same(did, "did:web:\(rpId):o:\(base32(lineHash))") else {
                    throw OpenEntityError("did_mismatch", "the genesis hash does not match the DID suffix")
                }
                let first = e.creds.count > 1 ? e.creds[1] : nil
                try fresh(e.creds)
                root = e.creds[0]
                single = first == nil
                approvers = first.map { [$0] } ?? []
                let s = first ?? e.creds[0]
                signer = same(s.kid, e.kid) ? s : nil
            case .addApprover:
                try fresh(e.creds)
                signer = approver(e.kid)
            case .recover:
                try fresh(e.creds)
                signer = isRoot(e.kid) ? root : nil
            case .replaceRoot:
                try fresh(e.creds)
                signer = isRoot(e.kid) ? root : approver(e.kid)
            case .cancel:
                guard let op = delayed[e.target] else {
                    throw OpenEntityError("bad_target", "target is not a recover or replace_root in this log")
                }
                signer = approver(e.kid)
                    ?? revoked.first { same($0.cred.kid, e.kid) && t < $0.at + week }?.cred
                    ?? (op == .recover && isRoot(e.kid) ? root : nil)
            case .revoke:
                guard approvers.contains(where: { same($0.kid, e.target) }) else {
                    throw OpenEntityError("bad_target", "kid is not a current approver")
                }
                signer = isRoot(e.kid) ? root : approver(e.kid)
            case .close:
                signer = services.first { same($0.kid, e.kid) }
            }
            guard let signer else { throw OpenEntityError("unauthorized", "key \(e.kid) may not sign \(e.op.rawValue) here") }
            _ = try checkSignature(signer, e.auth, message: e.signed, origins: origins, rpId: rpId, lowS: true)

            switch e.op {
            case .genesis:
                break
            case .addApprover:
                approvers.append(e.creds[0])
                single = false
            case .recover:
                pending.append(Pending(seq: seq, op: .recover, hash: hash, effectiveAt: t + day, creds: e.creds))
                delayed[hash] = .recover
            case .replaceRoot:
                if single {
                    root = e.creds[0]
                } else {
                    pending.append(Pending(seq: seq, op: .replaceRoot, hash: hash, effectiveAt: t + day, creds: e.creds))
                }
                delayed[hash] = .replaceRoot
            case .cancel:
                pending.removeAll { same($0.hash, e.target) }
            case .revoke:
                if let gone = approvers.firstIndex(where: { same($0.kid, e.target) }) {
                    revoked.append((approvers.remove(at: gone), t))
                }
            case .close:
                closed = true
                pending = []
            }
            head = hash
        }
        due(now)
        guard let root else { throw OpenEntityError("malformed", "a key log starts with its genesis entry") }
        return KeyLogState(
            did: did, seq: lines.count, head: head, root: root, approvers: single ? [root] : approvers,
            revoked: revoked.map { Revocation(kid: $0.cred.kid, at: $0.at) },
            pending: pending.map { PendingOperation(seq: $0.seq, op: $0.op.rawValue, hash: $0.hash, effectiveAt: $0.effectiveAt) },
            closed: closed)
    } catch {
        throw OpenEntityError(error.code, error.message, seq: seq)
    }
}

func parseEntry(_ line: String, rpId: String, first: Bool) throws(OpenEntityError) -> Entry {
    let e: JSONValue
    do throws(OpenEntityError) {
        e = try JSONValue.parse(line)
    } catch {
        throw OpenEntityError("malformed", error.message)
    }
    if let bad = plainError(e) { throw OpenEntityError("malformed", bad) }
    guard let canonical = try? canonicalize(e), same(canonical, line) else {
        throw OpenEntityError("malformed", "line is not the RFC 8785 form of its entry")
    }
    guard case .object(let members) = e, exactKeys(members, ["v", "seq", "prev", "op", "ts", "body", "auth"]) else {
        throw OpenEntityError("malformed", "entry must have exactly v, seq, prev, op, ts, body, auth")
    }
    guard case .number(1)? = e["v"] else { throw OpenEntityError("malformed", "v must be 1") }
    guard let seq = uint(e["seq"]), uint(e["ts"]) != nil else { throw OpenEntityError("malformed", "seq and ts must be unsigned integers") }
    var prev: String?
    switch e["prev"] {
    case .null?: prev = nil
    case .string(let p)? where isHex64(p): prev = p
    default: throw OpenEntityError("malformed", "prev must be null or 64 lowercase hex")
    }
    guard let name = e["op"]?.stringValue, let op = Op.allCases.first(where: { same($0.rawValue, name) }) else {
        throw OpenEntityError("malformed", "unknown op")
    }
    guard (op == .genesis) == first else { throw OpenEntityError("malformed", "genesis is the first entry and only the first") }
    guard let body = e["body"], case .object(let fields) = body, exactKeys(fields, op.body) else {
        throw OpenEntityError("malformed", "\(op.rawValue) body must have exactly: \(op.body.joined(separator: ", "))")
    }
    var creds: [Credential] = [], target = ""
    switch op {
    case .genesis, .replaceRoot:
        let root = try credential(body["root"], rpId: rpId, what: "root")
        guard same(root.type, "webauthn") else { throw OpenEntityError("malformed", "root must be a passkey (webauthn)") }
        creds = [root]
        if op == .genesis {
            switch body["approver"] {
            case .null?: break
            case let first:
                let approver = try credential(first, rpId: rpId, what: "approver")
                creds.append(approver)
            }
        }
    case .addApprover:
        creds = try [credential(body["approver"], rpId: rpId, what: "approver")]
    case .recover:
        guard let list = body["approvers"]?.arrayValue, !list.isEmpty else {
            throw OpenEntityError("malformed", "recover needs at least one approver")
        }
        for (n, c) in list.enumerated() {
            let cred = try credential(c, rpId: rpId, what: "approvers[\(n)]")
            creds.append(cred)
        }
    case .cancel:
        guard let t = body["target"]?.stringValue, isHex64(t) else { throw OpenEntityError("malformed", "target must be 64 lowercase hex") }
        target = t
    case .revoke:
        guard let k = body["kid"]?.stringValue else { throw OpenEntityError("malformed", "kid must be a string") }
        target = k
    case .close:
        break
    }
    guard let auth = e["auth"], case .object(let authFields) = auth, let kid = auth["kid"]?.stringValue else {
        throw OpenEntityError("malformed", "auth must be an object with a kid")
    }
    let webauthn = auth["form"]?.stringValue.map { same($0, "webauthn") } ?? false
    let keys = ["kid", "form", "signature"] + (webauthn ? ["authenticator_data", "client_data_json"] : [])
    if let shape = signedShape(auth) ?? (exactKeys(authFields, keys) ? nil : "auth must have exactly \(keys.joined(separator: ", "))") {
        throw OpenEntityError("malformed", shape)
    }
    let signed = try canonicalize(.object(members.filter { !same($0.key, "auth") }))
    return Entry(seq: seq, prev: prev, op: op, creds: creds, target: target, kid: kid, auth: auth, signed: Array(signed.utf8))
}

func credential(_ c: JSONValue?, rpId: String, what: String) throws(OpenEntityError) -> Credential {
    guard let c, case .object = c else { throw OpenEntityError("malformed", "\(what) must be a credential object") }
    guard let type = c["type"]?.stringValue, same(type, "p256") || same(type, "webauthn") else {
        throw OpenEntityError("malformed", "\(what).type must be p256 or webauthn")
    }
    guard let jwk = jwk(c["jwk"]), p256Key(jwk) != nil else {
        throw OpenEntityError("malformed", "\(what).jwk must be exactly {kty: EC, crv: P-256, x, y} with a point on the curve")
    }
    guard let kid = c["kid"]?.stringValue, same(kid, thumbprint(jwk)) else {
        throw OpenEntityError("malformed", "\(what).kid must be the RFC 7638 thumbprint of its jwk")
    }
    if same(type, "webauthn") {
        guard let id = b64u(c["credential_id"]), !id.isEmpty, let rp = c["rp_id"]?.stringValue, same(rp, rpId) else {
            throw OpenEntityError("malformed", "\(what) needs a credential_id and rp_id \(rpId)")
        }
    }
    return Credential(kid: kid, type: type, jwk: jwk, json: c)
}

// ---------------------------------------------------------------- signatures

/// Checks a p256 or webauthn signature by `cred` over SHA-256(`message`); returns the WebAuthn signature counter (0 for p256).
func checkSignature(_ cred: Credential, _ s: JSONValue, message: [UInt8], origins: [String], rpId: String,
                    lowS: Bool) throws(OpenEntityError) -> UInt32 {
    let form = s["form"]?.stringValue ?? ""
    guard same(form, cred.type) else { throw OpenEntityError("bad_signature", "a \(cred.type) key cannot present a \(form) signature") }
    guard let key = p256Key(cred.jwk), let sig = b64u(s["signature"]) else { throw OpenEntityError("bad_signature", "unreadable key or signature") }
    let digest = sha256(message)
    if same(form, "p256") {
        guard sig.count == 64, ecdsa(sig, message, key, lowS: lowS) else { throw OpenEntityError("bad_signature", "p256 signature does not verify") }
        return 0
    }
    guard let authData = b64u(s["authenticator_data"]), let clientRaw = b64u(s["client_data_json"]) else {
        throw OpenEntityError("bad_webauthn", "webauthn needs authenticator_data and client_data_json")
    }
    // Strict UTF-8 JSON: a byte order mark, a lone surrogate or a duplicate key is not client data.
    guard let client = try? JSONValue.parse(Data(clientRaw)) else { throw OpenEntityError("bad_webauthn", "clientDataJSON is not JSON") }
    if let odd = plainError(client, ints: false) { throw OpenEntityError("bad_webauthn", "clientDataJSON: \(odd)") }
    guard let type = client["type"]?.stringValue, same(type, "webauthn.get") else {
        throw OpenEntityError("bad_webauthn", "clientDataJSON type must be webauthn.get")
    }
    guard let challenge = client["challenge"]?.stringValue, same(challenge, b64url(digest)) else {
        throw OpenEntityError("bad_webauthn", "challenge is not the digest")
    }
    guard let origin = client["origin"]?.stringValue, origins.contains(where: { same($0, origin) }) else {
        throw OpenEntityError("bad_webauthn", "origin is not accepted")
    }
    if case .bool(true)? = client["crossOrigin"] { throw OpenEntityError("bad_webauthn", "cross-origin assertions are not accepted") }
    guard authData.count >= 37, authData[0..<32].elementsEqual(sha256(Array(rpId.utf8))) else {
        throw OpenEntityError("bad_webauthn", "rpIdHash is not SHA-256(\(rpId))")
    }
    guard authData[32] & 0x05 == 0x05 else {
        throw OpenEntityError("bad_webauthn", "user presence and user verification flags must be set")
    }
    guard let raw = derToRaw(sig), ecdsa(raw, authData + sha256(clientRaw), key, lowS: lowS) else {
        throw OpenEntityError("bad_signature", "webauthn signature does not verify")
    }
    return authData[33..<37].reduce(0) { $0 << 8 | UInt32($1) }
}

/// The signature fields shared by approvals and key log `auth`.
func signedShape(_ s: JSONValue) -> String? {
    guard let form = s["form"]?.stringValue, same(form, "p256") || same(form, "webauthn") else { return "form must be p256 or webauthn" }
    if b64u(s["signature"]) == nil { return "signature must be base64url" }
    if same(form, "webauthn") && (b64u(s["authenticator_data"]) == nil || b64u(s["client_data_json"]) == nil) {
        return "webauthn needs authenticator_data and client_data_json in base64url"
    }
    return nil
}

/// ECDSA P-256 over SHA-256(`message`). r and s must be in [1, n-1]; key log entries also need s <= n/2. CryptoKit
/// accepts either s, as approvals do.
func ecdsa(_ raw: [UInt8], _ message: [UInt8], _ key: P256.Signing.PublicKey, lowS: Bool) -> Bool {
    let r = Array(raw[0..<32]), s = Array(raw[32..<64])
    func inRange(_ x: [UInt8]) -> Bool { x.contains { $0 != 0 } && x.lexicographicallyPrecedes(order) }
    guard inRange(r), inRange(s), !(lowS && halfOrder.lexicographicallyPrecedes(s)),
          let signature = try? P256.Signing.ECDSASignature(rawRepresentation: raw) else { return false }
    return key.isValidSignature(signature, for: SHA256.hash(data: message))
}

/// Strict DER `SEQUENCE { INTEGER r, INTEGER s }` to 64-byte r || s: short-form lengths, minimal positive INTEGERs, nothing
/// after the sequence. Nil for any other encoding.
func derToRaw(_ der: [UInt8]) -> [UInt8]? {
    guard der.count >= 8, der[0] == 0x30, der[1] <= 0x7F, Int(der[1]) == der.count - 2 else { return nil }
    var out = [UInt8](repeating: 0, count: 64)
    var i = 2
    for at in [0, 32] {
        guard i + 1 < der.count, der[i] == 0x02 else { return nil }
        let len = Int(der[i + 1])
        guard (1...33).contains(len), i + 2 + len <= der.count else { return nil }
        let v = Array(der[(i + 2)..<(i + 2 + len)])
        if v[0] & 0x80 != 0 || (len > 1 && v[0] == 0 && v[1] & 0x80 == 0) || (len == 33 && v[0] != 0) { return nil }
        let int = len == 33 ? Array(v.dropFirst()) : v
        out.replaceSubrange((at + 32 - int.count)..<(at + 32), with: int)
        i += 2 + len
    }
    return i == der.count ? out : nil
}

/// The CryptoKit key for a P-256 JWK; nil unless kty, crv and strict 32-byte coordinates name a point on the curve.
func p256Key(_ j: JWK) -> P256.Signing.PublicKey? {
    guard same(j.kty, "EC"), same(j.crv, "P-256"), let x = b64u(.string(j.x)), let y = b64u(.string(j.y)), x.count == 32, y.count == 32
    else { return nil }
    return try? P256.Signing.PublicKey(x963Representation: [0x04] + x + y)
}

/// A JWK object with exactly kty, crv, x and y, all strings.
func jwk(_ v: JSONValue?) -> JWK? {
    guard case .object(let m)? = v, exactKeys(m, ["kty", "crv", "x", "y"]), let v,
          let kty = v["kty"]?.stringValue, let crv = v["crv"]?.stringValue, let x = v["x"]?.stringValue, let y = v["y"]?.stringValue
    else { return nil }
    return JWK(kty: kty, crv: crv, x: x, y: y)
}

/// RFC 7638 JWK thumbprint, base64url: the `kid` of every key in a log.
func thumbprint(_ j: JWK) -> String {
    b64url(sha256(Array("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(j.x)\",\"y\":\"\(j.y)\"}".utf8)))
}

// ---------------------------------------------------------------- small checks

func exactKeys(_ members: [(key: String, value: JSONValue)], _ keys: [String]) -> Bool {
    members.count == keys.count && keys.allSatisfy { k in members.contains { same($0.key, k) } }
}

/// A JSON number that is an integer in [0, 2^53 - 1].
func uint(_ v: JSONValue?) -> Int64? {
    guard let d = v?.numberValue, d >= 0, d <= Double(maxSafe), d.rounded(.towardZero) == d else { return nil }
    return Int64(d)
}

/// Containers on one path, in an entry, a payload summary or clientDataJSON: the same limit in all four SDKs.
let ownerMaxDepth = 64

/// Entries and payload summaries hold only integers within 2^53 - 1 (unless `ints` is false), strings without lone surrogates
/// (which the parser already refuses) and at most 64 nested containers, so every SDK reads them the same way.
func plainError(_ v: JSONValue, ints: Bool = true, depth: Int = 0) -> String? {
    switch v {
    case .number(let d):
        return !ints || (d.isFinite && d.rounded(.towardZero) == d && abs(d) <= Double(maxSafe)) ? nil : "number \(d) is not an integer within 2^53"
    // Plain loops: `lazy.compactMap { }.first` runs the closure twice on the way to the first hit, 2^depth calls down a nested path.
    case .array(let items):
        if depth >= ownerMaxDepth { return "nested deeper than \(ownerMaxDepth) levels" }
        for item in items { if let e = plainError(item, ints: ints, depth: depth + 1) { return e } }
        return nil
    case .object(let members):
        if depth >= ownerMaxDepth { return "nested deeper than \(ownerMaxDepth) levels" }
        for member in members { if let e = plainError(member.value, ints: ints, depth: depth + 1) { return e } }
        return nil
    default:
        return nil
    }
}

/// `did:<method>:` then `[A-Za-z0-9._%:-]`, not ending in `:`.
func isDID(_ s: String) -> Bool {
    let b = Array(s.utf8)
    guard b.starts(with: Array("did:".utf8)), let colon = b[4...].firstIndex(of: UInt8(ascii: ":")) else { return false }
    let method = b[4..<colon], id = b[(colon + 1)...]
    let idByte = { (c: UInt8) in isAlnum(c) || c == UInt8(ascii: ".") || c == UInt8(ascii: "_") || c == UInt8(ascii: "%") || c == UInt8(ascii: "-") }
    return !method.isEmpty && method.allSatisfy { (0x61...0x7A).contains($0) || (0x30...0x39).contains($0) }
        && !id.isEmpty && id.allSatisfy { idByte($0) || $0 == UInt8(ascii: ":") } && idByte(id.last!)
}

func isRequestIdByte(_ c: UInt8) -> Bool {
    isAlnum(c) || c == UInt8(ascii: ":") || c == UInt8(ascii: ".") || c == UInt8(ascii: "_") || c == UInt8(ascii: "-")
}

func isAlnum(_ c: UInt8) -> Bool { (0x41...0x5A).contains(c) || (0x61...0x7A).contains(c) || (0x30...0x39).contains(c) }

func isHex64(_ s: String) -> Bool { s.utf8.count == 64 && s.utf8.allSatisfy { (0x30...0x39).contains($0) || (0x61...0x66).contains($0) } }

func hexBytes(_ s: String) -> [UInt8] {
    let b = Array(s.utf8)
    return stride(from: 0, to: b.count, by: 2).map { UInt8(String(decoding: b[$0..<($0 + 2)], as: UTF8.self), radix: 16)! }
}

/// RFC 4648 base32, lowercase, no padding: the owner DID suffix.
func base32(_ bytes: [UInt8]) -> String {
    let alphabet = Array("abcdefghijklmnopqrstuvwxyz234567".utf8)
    var out: [UInt8] = [], bits = 0, value = 0
    for x in bytes {
        value = (value << 8) | Int(x)
        bits += 8
        while bits >= 5 {
            bits -= 5
            out.append(alphabet[(value >> bits) & 31])
        }
        value &= (1 << bits) - 1
    }
    if bits > 0 { out.append(alphabet[(value << (5 - bits)) & 31]) }
    return String(decoding: out, as: UTF8.self)
}
