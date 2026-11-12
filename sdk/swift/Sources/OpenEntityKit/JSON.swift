import CryptoKit
import Foundation

/// Every failure this package reports. `code` is a vector error code (`malformed`, `unauthorized`, `bad_signature`, ...),
/// `invalid_input` for a caller error, or `verification_failed` / `unsupported` for OEIS proofs. `seq` is the failing
/// key log entry (nil outside verifyKeyLog).
public struct OpenEntityError: Error, Equatable, Sendable {
    public let code: String
    public let seq: Int?
    public let message: String

    init(_ code: String, _ message: String, seq: Int? = nil) {
        self.code = code
        self.seq = seq
        self.message = message
    }
}

/// A JSON value as JavaScript's JSON.parse reads it: numbers are Doubles, objects keep their members in order.
/// Strings are compared byte for byte everywhere in this package, never with Swift's Unicode-equivalence `==`
/// (under which "K" equals the Kelvin sign U+212A).
public enum JSONValue: Sendable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([(key: String, value: JSONValue)])
}

extension JSONValue {
    /// The member named exactly `key`, or nil when this is not an object or has no such member.
    public subscript(key: String) -> JSONValue? {
        guard case .object(let members) = self else { return nil }
        return members.first { same($0.key, key) }?.value
    }
    public var stringValue: String? {
        if case .string(let s) = self { return s }
        return nil
    }
    public var numberValue: Double? {
        if case .number(let n) = self { return n }
        return nil
    }
    public var boolValue: Bool? {
        if case .bool(let b) = self { return b }
        return nil
    }
    public var arrayValue: [JSONValue]? {
        if case .array(let a) = self { return a }
        return nil
    }

    /// Spec 4.3 JSON: RFC 8259 text with no duplicate keys. Lone surrogate escapes are rejected (a Swift string cannot hold
    /// one). Throws `invalid_input`.
    public static func parse(_ text: String) throws(OpenEntityError) -> JSONValue {
        var p = JSONParser(b: Array(text.utf8))
        return try p.document()
    }

    /// The same from UTF-8 bytes; invalid UTF-8 is rejected, never repaired.
    public static func parse(_ data: Data) throws(OpenEntityError) -> JSONValue {
        guard let bytes = strictUTF8(data) else { throw OpenEntityError("invalid_input", "not JSON: invalid UTF-8") }
        var p = JSONParser(b: bytes)
        return try p.document()
    }
}

/// RFC 8785 (JCS): keys sorted by UTF-16 code units, strings escaped as JSON.stringify escapes them, numbers as ECMAScript
/// prints them. Throws `invalid_input` for NaN, Infinity or a duplicate key.
public func canonicalize(_ value: JSONValue) throws(OpenEntityError) -> String {
    var out: [UInt8] = []
    try jcs(value, &out)
    return String(decoding: out, as: UTF8.self)
}

func jcs(_ v: JSONValue, _ out: inout [UInt8]) throws(OpenEntityError) {
    switch v {
    case .null: out += Array("null".utf8)
    case .bool(let b): out += Array((b ? "true" : "false").utf8)
    case .number(let n):
        let s = try jcsNumber(n)
        out += Array(s.utf8)
    case .string(let s): quote(s, &out)
    case .array(let items):
        out.append(UInt8(ascii: "["))
        for (n, x) in items.enumerated() {
            if n > 0 { out.append(UInt8(ascii: ",")) }
            try jcs(x, &out)
        }
        out.append(UInt8(ascii: "]"))
    case .object(let members):
        let sorted = members.sorted { $0.key.utf16.lexicographicallyPrecedes($1.key.utf16) }
        out.append(UInt8(ascii: "{"))
        for (n, m) in sorted.enumerated() {
            if n > 0 {
                if same(sorted[n - 1].key, m.key) { throw OpenEntityError("invalid_input", "duplicate key \(m.key)") }
                out.append(UInt8(ascii: ","))
            }
            quote(m.key, &out)
            out.append(UInt8(ascii: ":"))
            try jcs(m.value, &out)
        }
        out.append(UInt8(ascii: "}"))
    }
}

/// ECMAScript JSON.stringify string escaping: the two-letter escapes, other C0 controls as lowercase \u00xx, the rest literal.
func quote(_ s: String, _ out: inout [UInt8]) {
    out.append(UInt8(ascii: "\""))
    for c in s.utf8 {
        switch c {
        case 0x22: out += [0x5C, 0x22]
        case 0x5C: out += [0x5C, 0x5C]
        case 0x08: out += [0x5C, UInt8(ascii: "b")]
        case 0x09: out += [0x5C, UInt8(ascii: "t")]
        case 0x0A: out += [0x5C, UInt8(ascii: "n")]
        case 0x0C: out += [0x5C, UInt8(ascii: "f")]
        case 0x0D: out += [0x5C, UInt8(ascii: "r")]
        case 0..<0x20: out += Array("\\u00".utf8) + Array(hex([c]).utf8)
        default: out.append(c)
        }
    }
    out.append(UInt8(ascii: "\""))
}

/// ECMAScript Number::toString. Swift's `description` already gives the shortest round-trip digits; this re-lays them out
/// (Python's `_num` does the same from `repr`).
func jcsNumber(_ x: Double) throws(OpenEntityError) -> String {
    guard x.isFinite else { throw OpenEntityError("invalid_input", "JCS: NaN and Infinity are not JSON") }
    if x == 0 { return "0" }
    let s = Array(abs(x).description.utf8)  // "100.0", "0.81", "1e-07", "1.2345e+20"
    let e = s.firstIndex(of: UInt8(ascii: "e"))
    let mantissa = s[..<(e ?? s.endIndex)]
    let exponent = e.flatMap { Int(String(decoding: s[($0 + 1)...], as: UTF8.self)) } ?? 0
    var digits = mantissa.filter { $0 != UInt8(ascii: ".") }
    var n = (mantissa.firstIndex(of: UInt8(ascii: ".")) ?? mantissa.endIndex) + exponent  // value = 0.digits * 10^n
    while digits.first == UInt8(ascii: "0") {
        digits.removeFirst()
        n -= 1
    }
    while digits.last == UInt8(ascii: "0") { digits.removeLast() }
    let d = String(decoding: digits, as: UTF8.self), k = digits.count
    let r: String
    if k <= n && n <= 21 {
        r = d + String(repeating: "0", count: n - k)
    } else if 0 < n && n <= 21 {
        r = String(d.prefix(n)) + "." + String(d.dropFirst(n))
    } else if -6 < n && n <= 0 {
        r = "0." + String(repeating: "0", count: -n) + d
    } else {
        r = String(d.prefix(1)) + (k > 1 ? "." + String(d.dropFirst()) : "") + "e" + (n - 1 < 0 ? "-" : "+") + String(abs(n - 1))
    }
    return (x < 0 ? "-" : "") + r
}

/// Recursive descent over UTF-8 bytes: RFC 8259 exactly as JSON.parse reads it, plus the spec 4.3 duplicate-key rule.
struct JSONParser {
    let b: [UInt8]
    var i = 0
    var depth = 0
    // ponytail: fixed nesting cap so hostile input cannot exhaust the stack; raise it if a real object ever nests deeper.
    static let maxDepth = 128

    var peek: UInt8? { i < b.count ? b[i] : nil }

    func bad(_ why: String) -> OpenEntityError { OpenEntityError("invalid_input", "not JSON: \(why) at byte \(i)") }

    mutating func document() throws(OpenEntityError) -> JSONValue {
        let v = try value()
        space()
        guard i == b.count else { throw bad("data after the value") }
        return v
    }

    mutating func space() {
        while let c = peek, c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D { i += 1 }
    }

    mutating func value() throws(OpenEntityError) -> JSONValue {
        space()
        switch peek {
        case UInt8(ascii: "{"): return try object()
        case UInt8(ascii: "["): return try array()
        case UInt8(ascii: "\""): return .string(try string())
        case UInt8(ascii: "t"): try literal("true"); return .bool(true)
        case UInt8(ascii: "f"): try literal("false"); return .bool(false)
        case UInt8(ascii: "n"): try literal("null"); return .null
        default: return .number(try number())
        }
    }

    mutating func literal(_ word: String) throws(OpenEntityError) {
        let w = Array(word.utf8)
        guard b[i...].starts(with: w) else { throw bad("unexpected token") }
        i += w.count
    }

    mutating func enter() throws(OpenEntityError) {
        depth += 1
        if depth > Self.maxDepth { throw bad("nested deeper than \(Self.maxDepth)") }
        i += 1
    }

    mutating func object() throws(OpenEntityError) -> JSONValue {
        try enter()
        var members: [(key: String, value: JSONValue)] = []
        var keys = Set<[UInt8]>()
        space()
        if peek == UInt8(ascii: "}") {
            i += 1
            depth -= 1
            return .object(members)
        }
        while true {
            space()
            guard peek == UInt8(ascii: "\"") else { throw bad("expected a key") }
            let key = try string()
            guard keys.insert(Array(key.utf8)).inserted else { throw bad("duplicate key \(key)") }
            space()
            guard peek == UInt8(ascii: ":") else { throw bad("expected :") }
            i += 1
            let v = try value()
            members.append((key, v))
            space()
            if peek == UInt8(ascii: ",") {
                i += 1
            } else if peek == UInt8(ascii: "}") {
                i += 1
                depth -= 1
                return .object(members)
            } else {
                throw bad("expected , or }")
            }
        }
    }

    mutating func array() throws(OpenEntityError) -> JSONValue {
        try enter()
        var items: [JSONValue] = []
        space()
        if peek == UInt8(ascii: "]") {
            i += 1
            depth -= 1
            return .array(items)
        }
        while true {
            let v = try value()
            items.append(v)
            space()
            if peek == UInt8(ascii: ",") {
                i += 1
            } else if peek == UInt8(ascii: "]") {
                i += 1
                depth -= 1
                return .array(items)
            } else {
                throw bad("expected , or ]")
            }
        }
    }

    mutating func string() throws(OpenEntityError) -> String {
        i += 1
        var out: [UInt8] = []
        while let c = peek {
            i += 1
            switch c {
            case UInt8(ascii: "\""):
                return String(decoding: out, as: UTF8.self)
            case UInt8(ascii: "\\"):
                guard let e = peek else { throw bad("unterminated string") }
                i += 1
                switch e {
                case UInt8(ascii: "\""), UInt8(ascii: "\\"), UInt8(ascii: "/"): out.append(e)
                case UInt8(ascii: "b"): out.append(0x08)
                case UInt8(ascii: "f"): out.append(0x0C)
                case UInt8(ascii: "n"): out.append(0x0A)
                case UInt8(ascii: "r"): out.append(0x0D)
                case UInt8(ascii: "t"): out.append(0x09)
                case UInt8(ascii: "u"):
                    var u = try hex4()
                    if (0xDC00...0xDFFF).contains(u) { throw bad("lone surrogate") }
                    if (0xD800...0xDBFF).contains(u) {
                        guard peek == UInt8(ascii: "\\"), i + 1 < b.count, b[i + 1] == UInt8(ascii: "u") else { throw bad("lone surrogate") }
                        i += 2
                        let low = try hex4()
                        guard (0xDC00...0xDFFF).contains(low) else { throw bad("lone surrogate") }
                        u = 0x10000 + ((u - 0xD800) << 10) + (low - 0xDC00)
                    }
                    guard let scalar = Unicode.Scalar(u) else { throw bad("bad escape") }
                    UTF8.encode(scalar) { out.append($0) }
                default:
                    throw bad("bad escape")
                }
            case 0..<0x20:
                throw bad("control character in string")
            default:
                out.append(c)  // the input is valid UTF-8, so multi-byte sequences copy through intact
            }
        }
        throw bad("unterminated string")
    }

    mutating func hex4() throws(OpenEntityError) -> UInt32 {
        guard i + 4 <= b.count, b[i..<(i + 4)].allSatisfy(isHexDigit),
              let u = UInt32(String(decoding: b[i..<(i + 4)], as: UTF8.self), radix: 16) else { throw bad("bad \\u escape") }
        i += 4
        return u
    }

    mutating func number() throws(OpenEntityError) -> Double {
        let start = i
        func digit(_ c: UInt8?) -> Bool { c.map { (0x30...0x39).contains($0) } ?? false }
        if peek == UInt8(ascii: "-") { i += 1 }
        if peek == UInt8(ascii: "0") {
            i += 1
        } else if digit(peek) {
            while digit(peek) { i += 1 }
        } else {
            throw bad("unexpected token")
        }
        if peek == UInt8(ascii: ".") {
            i += 1
            guard digit(peek) else { throw bad("bad number") }
            while digit(peek) { i += 1 }
        }
        if peek == UInt8(ascii: "e") || peek == UInt8(ascii: "E") {
            i += 1
            if peek == UInt8(ascii: "+") || peek == UInt8(ascii: "-") { i += 1 }
            guard digit(peek) else { throw bad("bad number") }
            while digit(peek) { i += 1 }
        }
        // Correctly rounded like JSON.parse; past the Double range it is +-Infinity, which canonicalize refuses.
        guard let d = Double(String(decoding: b[start..<i], as: UTF8.self)) else { throw bad("bad number") }
        return d
    }
}

// ---------------------------------------------------------------- bytes and strings

/// Byte-for-byte string equality (JavaScript `===` on well-formed strings).
func same(_ a: String, _ b: String) -> Bool { a.utf8.elementsEqual(b.utf8) }

func isHexDigit(_ c: UInt8) -> Bool {
    (0x30...0x39).contains(c) || (0x41...0x46).contains(c) || (0x61...0x66).contains(c)
}

/// The bytes when they are valid UTF-8, else nil. Decoding repairs invalid sequences, so a round trip that changes nothing
/// means there was nothing to repair.
func strictUTF8(_ data: some Collection<UInt8>) -> [UInt8]? {
    let bytes = Array(data)
    return Array(String(decoding: bytes, as: UTF8.self).utf8) == bytes ? bytes : nil
}

func hex(_ bytes: some Sequence<UInt8>) -> String {
    let digits = Array("0123456789abcdef".utf8)
    var out: [UInt8] = []
    for x in bytes { out += [digits[Int(x >> 4)], digits[Int(x & 15)]] }
    return String(decoding: out, as: UTF8.self)
}

func sha256(_ bytes: some DataProtocol) -> [UInt8] { Array(SHA256.hash(data: bytes)) }

/// Unpadded base64url.
func b64url(_ bytes: some Sequence<UInt8>) -> String {
    let url = Data(bytes).base64EncodedString().utf8.compactMap { c -> UInt8? in
        c == UInt8(ascii: "+") ? UInt8(ascii: "-") : c == UInt8(ascii: "/") ? UInt8(ascii: "_") : c == UInt8(ascii: "=") ? nil : c
    }
    return String(decoding: url, as: UTF8.self)
}

/// Strict base64url: the alphabet, no padding, and the one encoding of the bytes (re-encoding gives the same string).
func b64u(_ v: JSONValue?) -> [UInt8]? {
    guard let s = v?.stringValue else { return nil }
    let alphabet = s.utf8.allSatisfy { c in
        (0x41...0x5A).contains(c) || (0x61...0x7A).contains(c) || (0x30...0x39).contains(c) || c == UInt8(ascii: "-") || c == UInt8(ascii: "_")
    }
    guard alphabet, s.utf8.count % 4 != 1 else { return nil }
    let standard = s.utf8.map { $0 == UInt8(ascii: "-") ? UInt8(ascii: "+") : $0 == UInt8(ascii: "_") ? UInt8(ascii: "/") : $0 }
    let padded = String(decoding: standard, as: UTF8.self) + String(repeating: "=", count: (4 - standard.count % 4) % 4)
    guard let data = Data(base64Encoded: padded) else { return nil }
    return same(b64url(data), s) ? Array(data) : nil
}
