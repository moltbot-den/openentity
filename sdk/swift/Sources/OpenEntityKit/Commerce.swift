import CryptoKit
import Foundation

// OEIS Commerce Profile (spec/commerce-profile.md): mandate/1, cart/1, receipt/1 and the one-call checkout check. A port of
// sdk/ts/src/commerce.ts: the same checks in the same order with the same error codes. test-vectors/{mandate-1,cart-1,receipt-1,
// checkout-1} define all of it. Owners sign mandates on their devices and products verify, so there is no mandate signer here.
// Not here: verifying the agent's RFC 9421 request (pass the verified `agentDid`) and verifyReceiptChain.

let maxMandateTTL: Int64 = 90 * day
public let commerceRails = ["card", "x402", "mpp", "credits", "usdc"]
let mandatePeriods = ["P1D", "P7D", "P1M"]
let securityBands = ["poor", "fair", "good", "strong"]

// ---------------------------------------------------------------- shared checks

private func isPrefixedID(_ s: String?, _ prefix: String) -> Bool {
    guard let s, s.utf8.starts(with: prefix.utf8) else { return false }
    let rest = s.utf8.dropFirst(prefix.utf8.count)
    return rest.count == 26 && rest.allSatisfy { (0x61...0x7A).contains($0) || (0x32...0x37).contains($0) }
}

private func isCurrency(_ s: String?) -> Bool {
    guard let s else { return false }
    return s.utf8.count == 3 && s.utf8.allSatisfy { (0x41...0x5A).contains($0) }
}

private func isString(_ v: JSONValue?) -> Bool { v?.stringValue != nil }
private func isRail(_ v: JSONValue?) -> Bool { v?.stringValue.map { s in commerceRails.contains { same($0, s) } } ?? false }
private func has(_ m: [(key: String, value: JSONValue)], _ k: String) -> Bool { m.contains { same($0.key, k) } }
private func isNull(_ v: JSONValue?) -> Bool { if case .null? = v { return true } else { return false } }
private func members(_ v: JSONValue?) -> [(key: String, value: JSONValue)]? { if case .object(let m)? = v { return m } else { return nil } }

/// A non-empty array of strings of at most 253 UTF-16 units each.
private func strs(_ v: JSONValue?) -> [String]? {
    guard let a = v?.arrayValue else { return nil }
    let s = a.compactMap(\.stringValue)
    return s.count == a.count && s.allSatisfy { !$0.isEmpty && $0.utf16.count <= 253 } ? s : nil
}

// ---------------------------------------------------------------- cart/1

let cartKeys = ["profile", "merchant", "agent_did", "lines", "total", "currency", "rail", "mandate_id"]
let lineKeys = ["sku", "title", "qty", "unit"]

/// nil when `c` is a well-formed cart/1 summary, else why not.
public func cartError(_ c: JSONValue) -> String? {
    guard let m = members(c), exactKeys(m, cartKeys) else { return "cart/1 has exactly: \(cartKeys.joined(separator: ", "))" }
    guard let profile = c["profile"]?.stringValue, same(profile, "cart/1") else { return "profile must be cart/1" }
    guard let merchant = c["merchant"]?.stringValue, isDID(merchant) else { return "merchant must be a DID" }
    guard let agent = c["agent_did"]?.stringValue, isDID(agent) else { return "agent_did must be a DID" }
    guard isCurrency(c["currency"]?.stringValue) else { return "currency must be 3 uppercase letters" }
    guard isRail(c["rail"]) else { return "rail must be one of \(commerceRails.joined(separator: ", "))" }
    if !isNull(c["mandate_id"]) && !isPrefixedID(c["mandate_id"]?.stringValue, "md_") { return "mandate_id must be md_<26 base32> or null" }
    guard let lines = c["lines"]?.arrayValue, !lines.isEmpty, lines.count <= 100 else { return "lines must hold 1 to 100 lines" }
    var sum: Int64 = 0
    for l in lines {
        guard let lm = members(l) else { return "a line must be an object" }
        let withCategory = has(lm, "category")
        let keys = withCategory ? lineKeys + ["category"] : lineKeys
        guard exactKeys(lm, keys) else { return "a line has exactly: \(keys.joined(separator: ", "))" }
        guard let sku = l["sku"]?.stringValue, !sku.isEmpty, isString(l["title"]), !withCategory || isString(l["category"]) else {
            return "sku, title and category must be strings"
        }
        guard let qty = uint(l["qty"]), qty > 0, let unit = uint(l["unit"]) else { return "qty must be a positive integer and unit an integer in minor units" }
        // Past 2^53 no total can match (JavaScript rounds there, and total is at most 2^53 - 1), so an overflow is a mismatch.
        let (product, o1) = qty.multipliedReportingOverflow(by: unit)
        let (next, o2) = sum.addingReportingOverflow(product)
        sum = o1 || o2 ? Int64.max : next
    }
    guard let total = uint(c["total"]), total == sum else { return "total must equal the sum of qty * unit" }
    return plainError(c)
}

/// Lowercase hex payload digest of a cart/1 summary: the `payload_digest` of the approval/2.0 that approves this purchase.
/// Throws `invalid_input` for a cart that is not well formed.
public func cartDigest(_ cart: JSONValue) throws(OpenEntityError) -> String {
    if let e = cartError(cart) { throw OpenEntityError("invalid_input", e) }
    return try payloadDigest(cart)
}

// ---------------------------------------------------------------- mandate/1

public struct MandateLimits: Equatable, Sendable {
    public let currency: String
    public let perTxMax, periodMax, totalMax: Int64
    public let period: String
}

public struct MandateScope: Equatable, Sendable {
    public let merchants: [String]
    public let categories: [String]?
    public let rails: [String]
}

/// What a mandate lets an agent do: all that `mandateCovers` reads.
public struct MandateTerms: Equatable, Sendable {
    public let mandateId, agentDid: String
    public let limits: MandateLimits
    public let scope: MandateScope
    public let stepUpOver: Int64

    /// The terms of a mandate object (verified or not: `verifyMandate` is the check). Throws `invalid_input`.
    public init(_ m: JSONValue) throws(OpenEntityError) {
        guard let id = m["mandate_id"]?.stringValue, let agent = m["agent_did"]?.stringValue, let l = m["limits"], let s = m["scope"],
              let currency = l["currency"]?.stringValue, let period = l["period"]?.stringValue, let perTx = uint(l["per_tx_max"]),
              let periodMax = uint(l["period_max"]), let totalMax = uint(l["total_max"]), let merchants = s["merchants"]?.arrayValue?.compactMap(\.stringValue),
              let rails = s["rails"]?.arrayValue?.compactMap(\.stringValue), let stepUp = uint(m["step_up_over"])
        else { throw OpenEntityError("invalid_input", "not a mandate/1 object") }
        self.mandateId = id
        self.agentDid = agent
        self.limits = MandateLimits(currency: currency, perTxMax: perTx, periodMax: periodMax, totalMax: totalMax, period: period)
        self.scope = MandateScope(merchants: merchants, categories: s["categories"]?.arrayValue?.compactMap(\.stringValue), rails: rails)
        self.stepUpOver = stepUp
    }
}

let mandateKeys = ["version", "mandate_id", "issuer_did", "agent_did", "issued_at", "expires_at", "limits", "scope", "step_up_over", "status", "signature"]

/// JavaScript's `\s`: what `[^\s]+` in the status URL rule refuses.
private func isJSSpace(_ u: Unicode.Scalar) -> Bool {
    switch u.value {
    case 0x09...0x0D, 0x20, 0xA0, 0x1680, 0x2000...0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF: return true
    default: return false
    }
}

private func mandateFieldsError(_ m: JSONValue, _ ms: [(key: String, value: JSONValue)]) -> String? {
    if ms.contains(where: { k in !mandateKeys.contains { same($0, k.key) } && !same(k.key, "ap2") }) || mandateKeys.contains(where: { !has(ms, $0) }) {
        return "mandate/1 has \(mandateKeys.joined(separator: ", ")) and optionally ap2"
    }
    guard isPrefixedID(m["mandate_id"]?.stringValue, "md_") else { return "mandate_id must be md_<26 base32>" }
    guard let issuer = m["issuer_did"]?.stringValue, isDID(issuer) else { return "issuer_did must be a DID" }
    guard let agent = m["agent_did"]?.stringValue, isDID(agent) else { return "agent_did must be a DID" }
    guard let issued = uint(m["issued_at"]), let expires = uint(m["expires_at"]), expires > issued else {
        return "issued_at and expires_at must be unix seconds, expires after issued"
    }
    if expires - issued > maxMandateTTL { return "a mandate lasts at most 90 days" }
    guard let lm = members(m["limits"]), exactKeys(lm, ["currency", "per_tx_max", "period", "period_max", "total_max"]), let l = m["limits"] else {
        return "limits must be {currency, per_tx_max, period, period_max, total_max}"
    }
    guard isCurrency(l["currency"]?.stringValue), let period = l["period"]?.stringValue, mandatePeriods.contains(where: { same($0, period) }) else {
        return "limits.currency must be 3 uppercase letters and period one of \(mandatePeriods.joined(separator: ", "))"
    }
    guard uint(l["per_tx_max"]) != nil, uint(l["period_max"]) != nil, uint(l["total_max"]) != nil else { return "limits amounts must be integers in minor units" }
    guard let sm = members(m["scope"]), let s = m["scope"], !sm.contains(where: { k in !["merchants", "categories", "rails"].contains { same($0, k.key) } }),
          has(sm, "merchants"), has(sm, "rails") else { return "scope must be {merchants, categories?, rails}" }
    guard strs(s["merchants"]) != nil, !has(sm, "categories") || strs(s["categories"]) != nil else {
        return "scope.merchants and scope.categories must be arrays of strings"
    }
    guard let rails = s["rails"]?.arrayValue, !rails.isEmpty, rails.allSatisfy({ isRail($0) }) else {
        return "scope.rails must be a non-empty subset of \(commerceRails.joined(separator: ", "))"
    }
    guard uint(m["step_up_over"]) != nil else { return "step_up_over must be an integer in minor units" }
    guard let status = m["status"]?.stringValue, status.utf8.starts(with: "https://".utf8), status.utf8.count > 8,
          !status.unicodeScalars.dropFirst(8).contains(where: isJSSpace) else { return "status must be an https URL" }
    if has(ms, "ap2") {
        let ap2 = m["ap2"]
        guard let am = members(ap2), exactKeys(am, ["checkout_mandate_hash"]), isNull(ap2?["checkout_mandate_hash"]) || isString(ap2?["checkout_mandate_hash"]) else {
            return "ap2 must be {checkout_mandate_hash: string | null}"
        }
    }
    guard let sm2 = members(m["signature"]), let sig = m["signature"], isString(sig["device_id"]) else { return "signature must hold device_id, form, signature" }
    let sigKeys = sig["form"]?.stringValue.map { same($0, "webauthn") } == true
        ? ["device_id", "form", "signature", "authenticator_data", "client_data_json"] : ["device_id", "form", "signature"]
    if let shape = signedShape(sig) { return shape }
    return exactKeys(sm2, sigKeys) ? plainError(m) : "signature must have exactly \(sigKeys.joined(separator: ", "))"
}

private func mandateMessage(_ m: JSONValue) throws(OpenEntityError) -> [UInt8] {
    guard case .object(let ms) = m else { throw OpenEntityError("invalid_input", "mandate must be an object") }
    return Array(("mandate/1|*|" + (try canonicalize(.object(ms.filter { !same($0.key, "signature") })))).utf8)
}

/// SHA-256 of `mandate/1|*|` + the RFC 8785 form of the mandate without its signature. The `*` is the verifier scope: any merchant
/// may rely on it. Throws `invalid_input` for a non-object.
public func mandateDigest(_ mandate: JSONValue) throws(OpenEntityError) -> Data { Data(sha256(try mandateMessage(mandate))) }

/// A mandate that passed `verifyMandate`. `periodSpent` and `totalSpent` come from the status answer, when there was one.
public struct VerifiedMandate: Sendable {
    public let kid: String
    public let terms: MandateTerms
    public let issuerDid: String
    public let periodSpent, totalSpent: Int64?
    public var mandateId: String { terms.mandateId }
}

/// Verifies a mandate/1 against the issuer's key log and returns its terms, or throws `OpenEntityError` with the code from
/// mandate-1 (`malformed`, `bad_version`, `wrong_owner`, `owner_closed`, `wrong_agent`, `not_yet_valid`, `expired`, `unknown_key`,
/// `bad_signature`, `bad_webauthn`, `revoked`, `exhausted`, `status_required`). `agentDid` is the agent presenting the mandate (from
/// its verified request); omit it only to inspect a mandate. `status` is the answer of the mandate's status URL, fetched by the
/// caller (max-age 60 or less); without one a mandate is accepted only if it expires within a day. A status answer that is not
/// exactly what the profile says (including JSON null) is `status_required`. Revocation is `status`; spend accounting stays with
/// the enforcing product.
public func verifyMandate(_ mandate: JSONValue, keyLog: some OwnerKeys, agentDid: String? = nil, now: Int64, status: JSONValue? = nil,
                          origins: [String]? = nil, rpId: String = defaultRpId) throws(OpenEntityError) -> VerifiedMandate {
    guard let ms = members(mandate) else { throw OpenEntityError("malformed", "mandate must be an object") }
    guard let version = mandate["version"]?.stringValue, same(version, "mandate/1") else {
        throw OpenEntityError("bad_version", "version is not mandate/1")
    }
    if let bad = mandateFieldsError(mandate, ms) { throw OpenEntityError("malformed", bad) }
    let terms = try MandateTerms(mandate)
    let issuer = mandate["issuer_did"]?.stringValue ?? "", issued = uint(mandate["issued_at"]) ?? 0, expires = uint(mandate["expires_at"]) ?? 0
    guard same(issuer, keyLog.did) else { throw OpenEntityError("wrong_owner", "the mandate names another owner") }
    guard !keyLog.closed else { throw OpenEntityError("owner_closed", "the owner's key log is closed") }
    if let agentDid, !same(terms.agentDid, agentDid) { throw OpenEntityError("wrong_agent", "the mandate is for another agent") }
    guard now >= issued else { throw OpenEntityError("not_yet_valid", "the mandate is issued in the future") }
    guard now < expires else { throw OpenEntityError("expired", "the mandate expired") }
    let sig = mandate["signature"] ?? .null
    guard let cred = keyLog.approvers.first(where: { same($0.kid, sig["device_id"]?.stringValue ?? "") }) else {
        throw OpenEntityError("unknown_key", "device_id is not a current approver in the owner's key log")
    }
    _ = try checkSignature(cred, sig, message: try mandateMessage(mandate), origins: origins ?? ["https://\(rpId)"], rpId: rpId, lowS: false)
    var period: Int64?, total: Int64?
    if let status {
        // A status answer that is not exactly what the profile says is no answer: it never lets a mandate through.
        let state = status["status"]?.stringValue
        let wrongMandate = status["mandate_id"].map { !($0.stringValue.map { same($0, terms.mandateId) } ?? false) } ?? false
        let badSpent = [status["period_spent"], status["total_spent"]].contains { $0 != nil && uint($0) == nil }
        guard case .object = status, let state, ["active", "revoked", "exhausted"].contains(where: { same($0, state) }), !wrongMandate, !badSpent else {
            throw OpenEntityError("status_required", "the status answer is malformed or for another mandate")
        }
        if same(state, "revoked") { throw OpenEntityError("revoked", "the owner revoked the mandate") }
        if same(state, "exhausted") { throw OpenEntityError("exhausted", "the mandate is spent") }
        period = uint(status["period_spent"])
        total = uint(status["total_spent"])
    } else if expires - now > day {
        throw OpenEntityError("status_required", "a mandate with more than a day left needs a fresh status answer")
    }
    return VerifiedMandate(kid: cred.kid, terms: terms, issuerDid: issuer, periodSpent: period, totalSpent: total)
}

private let hostBytes = Set("abcdefghijklmnopqrstuvwxyz0123456789.-".utf8)

/// The host of a did:web DID, lowercase, without port; nil for other methods and for anything that is not a plain hostname
/// (%2F, %23, %3F, a bad escape).
private func didHost(_ did: String) -> String? {
    guard did.utf8.starts(with: "did:web:".utf8) else { return nil }
    let first = did.utf8.dropFirst(8).split(separator: UInt8(ascii: ":"), maxSplits: 1, omittingEmptySubsequences: false)[0]
    guard let d = String(decoding: first, as: UTF8.self).removingPercentEncoding?.lowercased() else { return nil }
    let parts = d.utf8.split(separator: UInt8(ascii: ":"), maxSplits: 1, omittingEmptySubsequences: false)
    let host = Array(parts[0])
    guard parts.count <= 2, let a = host.first, let z = host.last, host.allSatisfy(hostBytes.contains),
          hostBytes.contains(a), a != 0x2E, a != 0x2D, z != 0x2E, z != 0x2D else { return nil }
    if parts.count == 2, parts[1].isEmpty || !parts[1].allSatisfy({ (0x30...0x39).contains($0) }) { return nil }
    return String(decoding: host, as: UTF8.self)
}

private func merchantAllowed(_ patterns: [String], _ merchant: String) -> Bool {
    if patterns.isEmpty { return true }
    let host = didHost(merchant)
    return patterns.contains { p in
        if same(p, merchant) { return true }
        guard !p.utf8.starts(with: "did:".utf8), let host else { return false }
        let d = p.lowercased()
        return d.utf8.starts(with: "*.".utf8) ? host.utf8.reversed().starts(with: d.utf8.dropFirst().reversed()) : same(host, d)
    }
}

/// The answer of `mandateCovers`. `reason` is one of `bad_cart`, `wrong_agent`, `wrong_mandate`, `wrong_currency`, `out_of_scope`,
/// `over_limit`. `stepUpRequired` means the cart fits but is above `stepUpOver`: the owner must approve this exact cart
/// (approval/2.0 over `cartDigest`).
public struct MandateCover: Equatable, Sendable {
    public let ok, stepUpRequired: Bool
    public let reason, detail: String?
}

/// Whether a verified mandate allows this cart. `periodSpent` and `totalSpent` are what the enforcing product has recorded;
/// a negative one never fits.
public func mandateCovers(_ mandate: MandateTerms, cart: JSONValue, periodSpent: Int64? = nil, totalSpent: Int64? = nil) -> MandateCover {
    func no(_ reason: String, _ detail: String) -> MandateCover { MandateCover(ok: false, stepUpRequired: false, reason: reason, detail: detail) }
    if let bad = cartError(cart) { return no("bad_cart", bad) }
    let l = mandate.limits, s = mandate.scope
    let agent = cart["agent_did"]?.stringValue ?? "", merchant = cart["merchant"]?.stringValue ?? "", rail = cart["rail"]?.stringValue ?? ""
    let currency = cart["currency"]?.stringValue ?? "", total = uint(cart["total"]) ?? 0
    guard same(agent, mandate.agentDid) else { return no("wrong_agent", "the cart is for another agent") }
    if let id = cart["mandate_id"]?.stringValue, !same(id, mandate.mandateId) { return no("wrong_mandate", "the cart names another mandate") }
    guard same(currency, l.currency) else { return no("wrong_currency", "the mandate is in \(l.currency)") }
    guard s.rails.contains(where: { same($0, rail) }) else { return no("out_of_scope", "rail \(rail) is not in scope") }
    guard merchantAllowed(s.merchants, merchant) else { return no("out_of_scope", "merchant \(merchant) is not in scope") }
    if let cats = s.categories, !cats.isEmpty {
        let lines = cart["lines"]?.arrayValue ?? []
        if lines.contains(where: { line in !(line["category"]?.stringValue.map { c in cats.contains { same($0, c) } } ?? false) }) {
            return no("out_of_scope", "a line is outside the categories")
        }
    }
    if (periodSpent ?? 0) < 0 || (totalSpent ?? 0) < 0 { return no("over_limit", "spent must be unsigned integers") }
    if total > l.perTxMax { return no("over_limit", "per_tx_max") }
    if (periodSpent ?? 0) + total > l.periodMax { return no("over_limit", "period_max") }
    if (totalSpent ?? 0) + total > l.totalMax { return no("over_limit", "total_max") }
    return MandateCover(ok: true, stepUpRequired: total > mandate.stepUpOver, reason: nil, detail: nil)
}

// ---------------------------------------------------------------- receipt/1

public enum Party: String, Sendable { case merchant, agent }

let receiptKeys = ["version", "receipt_id", "kind", "refers_to", "merchant_did", "agent_did", "mandate_id", "mandate_hash", "cart_digest",
                   "approval_request_id", "total", "currency", "rail", "settlement_ref", "created_at"]

/// nil when `r` is a well-formed receipt/1 (proofs aside), else why not.
public func receiptError(_ r: JSONValue) -> String? {
    guard let m = members(r) else { return "receipt must be an object" }
    if m.contains(where: { k in !receiptKeys.contains { same($0, k.key) } && !same(k.key, "proofs") }) || receiptKeys.contains(where: { !has(m, $0) }) {
        return "receipt/1 has exactly: \(receiptKeys.joined(separator: ", ")), proofs"
    }
    guard let version = r["version"]?.stringValue, same(version, "receipt/1") else { return "version must be receipt/1" }
    guard isPrefixedID(r["receipt_id"]?.stringValue, "rc_") else { return "receipt_id must be rc_<26 base32>" }
    guard let kind = r["kind"]?.stringValue, ["purchase", "refund", "chargeback"].contains(where: { same($0, kind) }) else {
        return "kind must be purchase, refund or chargeback"
    }
    if same(kind, "purchase") ? !isNull(r["refers_to"]) : !isPrefixedID(r["refers_to"]?.stringValue, "rc_") {
        return "refers_to is null for a purchase and the purchase's receipt_id for a refund or chargeback"
    }
    guard let merchant = r["merchant_did"]?.stringValue, isDID(merchant), let agent = r["agent_did"]?.stringValue, isDID(agent) else {
        return "merchant_did and agent_did must be DIDs"
    }
    if same(merchant, agent) { return "merchant_did and agent_did must differ" }
    if !isNull(r["mandate_id"]) && !isPrefixedID(r["mandate_id"]?.stringValue, "md_") { return "mandate_id must be md_<26 base32> or null" }
    if !isNull(r["mandate_hash"]) && !(r["mandate_hash"]?.stringValue.map(isHex64) ?? false) { return "mandate_hash must be 64 lowercase hex or null" }
    if isNull(r["mandate_id"]) != isNull(r["mandate_hash"]) { return "mandate_id and mandate_hash go together" }
    guard r["cart_digest"]?.stringValue.map(isHex64) ?? false else { return "cart_digest must be 64 lowercase hex" }
    if !isNull(r["approval_request_id"]) {
        guard let id = r["approval_request_id"]?.stringValue, (1...128).contains(id.utf8.count), id.utf8.allSatisfy(isRequestIdByte) else {
            return "approval_request_id must be a request id or null"
        }
    }
    guard uint(r["total"]) != nil, uint(r["created_at"]) != nil else { return "total and created_at must be unsigned integers" }
    guard isCurrency(r["currency"]?.stringValue) else { return "currency must be 3 uppercase letters" }
    guard isRail(r["rail"]) else { return "rail must be one of \(commerceRails.joined(separator: ", "))" }
    guard let ref = r["settlement_ref"]?.stringValue, !ref.isEmpty, ref.utf16.count <= 256 else { return "settlement_ref must be 1 to 256 characters" }
    if let proofs = r["proofs"], proofs.arrayValue == nil { return "proofs must be an array" }
    return plainError(r)
}

/// The did:key of an Ed25519 public key.
public func didKey(_ key: Curve25519.Signing.PublicKey) -> String { "did:key:z" + base58Encode([0xED, 0x01] + Array(key.rawRepresentation)) }

/// base58btc (Bitcoin alphabet).
func base58Encode(_ bytes: [UInt8]) -> String {
    let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)
    var digits: [UInt8] = []  // little endian base 58
    for b in bytes {
        var carry = Int(b)
        for i in digits.indices {
            carry += Int(digits[i]) << 8
            digits[i] = UInt8(carry % 58)
            carry /= 58
        }
        while carry > 0 {
            digits.append(UInt8(carry % 58))
            carry /= 58
        }
    }
    let zeros = bytes.prefix { $0 == 0 }.count
    return String(decoding: [UInt8](repeating: alphabet[0], count: zeros) + digits.reversed().map { alphabet[Int($0)] }, as: UTF8.self)
}

/// Adds `by`'s eddsa-jcs-2022 proof. Both parties sign the same bytes (the receipt without `proofs`), so the buyer countersigns
/// without seeing the merchant's proof. `key` must belong to the receipt's `merchant_did` or `agent_did` named by `by`: a did:key
/// signer needs nothing more, a did:web merchant passes its own `verificationMethod`. `created` is an ISO 8601 UTC time without
/// fractions, default now. Throws `invalid_input`.
public func signReceipt(_ receipt: JSONValue, by: Party, key: Curve25519.Signing.PrivateKey, created: String? = nil,
                        verificationMethod: String? = nil) throws(OpenEntityError) -> JSONValue {
    if let e = receiptError(receipt) { throw OpenEntityError("invalid_input", e) }
    let did = didKey(key.publicKey)
    let method = verificationMethod ?? "\(did)#\(did.dropFirst("did:key:".count))"
    let signer = String(decoding: method.utf8.prefix { $0 != UInt8(ascii: "#") }, as: UTF8.self)
    guard let party = receipt["\(by.rawValue)_did"]?.stringValue, same(signer, party) else {
        throw OpenEntityError("invalid_input", "\(by.rawValue)_did is not the signing key's DID")
    }
    var proofs = receipt["proofs"]?.arrayValue ?? []
    if proofs.contains(where: { $0["by"]?.stringValue.map { same($0, by.rawValue) } ?? false }) {
        throw OpenEntityError("invalid_input", "already signed by \(by.rawValue)")
    }
    let config: [(key: String, value: JSONValue)] = [
        ("type", .string("DataIntegrityProof")), ("cryptosuite", .string("eddsa-jcs-2022")),
        ("created", .string(created ?? ISO8601DateFormatter().string(from: Date()))), ("verificationMethod", .string(method)),
        ("proofPurpose", .string("assertionMethod")),
    ]
    guard case .object(let rm) = receipt else { throw OpenEntityError("invalid_input", "receipt must be an object") }
    let body = JSONValue.object(rm.filter { !same($0.key, "proofs") })
    let message = sha256(Array(try canonicalize(.object(config)).utf8)) + sha256(Array(try canonicalize(body).utf8))
    guard let signature = try? key.signature(for: message) else { throw OpenEntityError("invalid_input", "signing failed") }
    proofs.append(.object([("by", .string(by.rawValue))] + config + [("proofValue", .string("z" + base58Encode(Array(signature))))]))
    return .object(rm.filter { !same($0.key, "proofs") } + [("proofs", .array(proofs))])
}

/// Who signed a receipt, in proof order.
public struct ReceiptVerified: Equatable, Sendable { public let signedBy: [Party] }

/// Verifies the proofs on a receipt: any proof present must verify, and its signer must be the receipt's `merchant_did` or
/// `agent_did` named by `by`. `require` (default merchant only) lists who must have signed. Throws `malformed`, `missing_proof`,
/// `wrong_signer` or `bad_proof`. did:key signers verify offline; pass `resolver` for a did:web merchant.
public func verifyReceipt(_ receipt: JSONValue, require: [Party] = [.merchant], resolver: DIDWebResolver? = nil) async throws(OpenEntityError) -> ReceiptVerified {
    if let e = receiptError(receipt) { throw OpenEntityError("malformed", e) }
    var signed: [Party] = []
    for p in receipt["proofs"]?.arrayValue ?? [] {
        guard case .object(let pm) = p, let by = p["by"]?.stringValue.flatMap(Party.init(rawValue:)), !signed.contains(by) else {
            throw OpenEntityError("malformed", "each proof names a distinct by: merchant or agent")
        }
        let proof = JSONValue.object(pm.filter { !same($0.key, "by") })
        guard let method = proof["verificationMethod"]?.stringValue, let party = receipt["\(by.rawValue)_did"]?.stringValue,
              same(String(decoding: method.utf8.prefix { $0 != UInt8(ascii: "#") }, as: UTF8.self), party) else {
            throw OpenEntityError("wrong_signer", "the \(by.rawValue) proof is not by \(by.rawValue)_did")
        }
        do throws(OpenEntityError) {
            if let resolver { _ = try await verifyProof(receipt, proof, resolver: resolver) } else { _ = try verifyProof(receipt, proof) }
        } catch {
            throw OpenEntityError("bad_proof", "\(by.rawValue): \(error.message)")
        }
        signed.append(by)
    }
    for need in require where !signed.contains(need) { throw OpenEntityError("missing_proof", "no \(need.rawValue) proof") }
    return ReceiptVerified(signedBy: signed)
}

// ---------------------------------------------------------------- the checkout check

/// What the merchant demands of an agent.
public struct AgentPolicy: Sendable {
    public var minLevel: Int64?
    public var requireOwner = false, requireMandate = false
    public var minSecurityBand: String?
    public var acceptIssuers: [String] = []
    public init() {}
}

/// What the caller knows about the agent from the registry (trust()): never taken from the request.
public struct AgentFacts: Sendable {
    public var level: Int64?
    public var ownerDid, securityBand, securityIssuer: String?
    public init() {}
}

/// The owner's per-cart approval/2.0 for this exact cart: `verifierDid` and `requestId` are the merchant's own. `counter` is the
/// WebAuthn counter stored for the signing key; store `approvalCounter` from the evidence after an allow.
public struct CheckoutApproval: Sendable {
    public let approval: JSONValue
    public let verifierDid, requestId: String
    public let counter: UInt32

    public init(approval: JSONValue, verifierDid: String, requestId: String, counter: UInt32 = 0) {
        self.approval = approval
        self.verifierDid = verifierDid
        self.requestId = requestId
        self.counter = counter
    }
}

public struct CheckoutEvidence: Equatable, Sendable {
    public var agentDid, mandateId, mandateHash, approvalRequestId, approvalKid, approvalError: String?
    public var approvalCounter: UInt32?
}

public struct CheckoutDecision: Sendable {
    /// `allow`, `step_up` or `deny`.
    public let decision: String
    public let reasons: [String]
    public let evidence: CheckoutEvidence
}

/// The one-call check behind Agent Commerce Check: agent, owner, mandate, cart and merchant policy in, `allow`, `step_up` or `deny`
/// with reasons out. Deny is final (bad cart, wrong agent, dead mandate, policy unmet); `step_up` means an owner approval of this
/// exact cart would allow. `agentDid` is the agent whose signed request the caller already verified (this SDK has no RFC 9421
/// verifier); nil denies `request_unverified`. `keyLog` is the mandate issuer's, and `status` the mandate status answer.
public func verifyAgentForCheckout(agentDid: String?, cart: JSONValue, policy: AgentPolicy, agent facts: AgentFacts = AgentFacts(),
                                   mandate: JSONValue? = nil, keyLog: (any OwnerKeys)? = nil, status: JSONValue? = nil,
                                   approval: CheckoutApproval? = nil, now: Int64, origins: [String]? = nil) -> CheckoutDecision {
    var evidence = CheckoutEvidence()
    func deny(_ reasons: String...) -> CheckoutDecision { CheckoutDecision(decision: "deny", reasons: reasons, evidence: evidence) }
    if cartError(cart) != nil { return deny("bad_cart") }
    guard let agent = agentDid else { return deny("request_unverified") }
    evidence.agentDid = agent
    guard let cartAgent = cart["agent_did"]?.stringValue, same(cartAgent, agent) else { return deny("agent_mismatch") }

    // Merchant policy on the agent itself.
    var reasons: [String] = []
    if let min = policy.minLevel, !((facts.level ?? -1) >= min) { reasons.append("level_too_low") }
    if let band = policy.minSecurityBand {
        let need = securityBands.firstIndex { same($0, band) } ?? -1, got = securityBands.firstIndex { same($0, facts.securityBand ?? "") } ?? -1
        if got < 0 || got < need { reasons.append("security_band_too_low") }
        else if !policy.acceptIssuers.isEmpty && !policy.acceptIssuers.contains(where: { same($0, facts.securityIssuer ?? "") }) { reasons.append("issuer_not_accepted") }
    }

    // Mandate.
    var owner = facts.ownerDid, covered: MandateCover?
    if let mandate {
        guard let keyLog else { return deny("no_key_log") }
        let v: VerifiedMandate
        do throws(OpenEntityError) {
            v = try verifyMandate(mandate, keyLog: keyLog, agentDid: agent, now: now, status: status, origins: origins)
        } catch {
            return deny("mandate_\(error.code)")
        }
        owner = v.issuerDid
        evidence.mandateId = v.mandateId
        evidence.mandateHash = (try? mandateDigest(mandate)).map { hex($0) }
        let c = mandateCovers(v.terms, cart: cart, periodSpent: v.periodSpent, totalSpent: v.totalSpent)
        covered = c
        if !c.ok, let r = c.reason, r != "over_limit", r != "out_of_scope" { return deny("mandate_\(r)") }
    } else if policy.requireMandate {
        reasons.append("mandate_required")
    }
    if policy.requireOwner && owner == nil { reasons.append("owner_unknown") }
    if !reasons.isEmpty { return CheckoutDecision(decision: "deny", reasons: reasons, evidence: evidence) }

    // Per-cart approval: needed when there is no mandate, the mandate does not cover the cart, or the cart is over step_up_over.
    guard let c = covered, c.ok, !c.stepUpRequired else {
        let why = covered.map { $0.ok ? "step_up_over" : "mandate_\($0.reason ?? "")" } ?? "no_mandate"
        if let approval, let keyLog, let owner, let digest = try? cartDigest(cart) {
            do throws(OpenEntityError) {
                let a = try verifyApproval(approval.approval, keyLog: keyLog, verifierDid: approval.verifierDid, ownerDid: owner, requestId: approval.requestId,
                                           payloadDigest: digest, now: now, decisions: ["approve"], origins: origins, counter: approval.counter)
                evidence.approvalRequestId = approval.requestId
                evidence.approvalKid = a.kid
                evidence.approvalCounter = a.counter
                return CheckoutDecision(decision: "allow", reasons: ["owner_approved_cart", why], evidence: evidence)
            } catch {
                evidence.approvalError = error.code
            }
        }
        return CheckoutDecision(decision: "step_up", reasons: [why], evidence: evidence)
    }
    return CheckoutDecision(decision: "allow", reasons: ["mandate_covers_cart"], evidence: evidence)
}
