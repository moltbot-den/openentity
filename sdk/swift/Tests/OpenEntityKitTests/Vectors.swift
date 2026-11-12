import Foundation
import OpenEntityKit

/// test-vectors/ at the repo root: this file is sdk/swift/Tests/OpenEntityKitTests/Vectors.swift.
let vectorsDir = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    .deletingLastPathComponent().deletingLastPathComponent()
    .appendingPathComponent("test-vectors")

func vector(_ path: String) throws -> JSONValue {
    try JSONValue.parse(String(contentsOf: vectorsDir.appendingPathComponent(path), encoding: .utf8))
}

func vectorFiles(_ dir: String, prefix: String = "") -> [String] {
    let names = (try? FileManager.default.contentsOfDirectory(atPath: vectorsDir.appendingPathComponent(dir).path)) ?? []
    return names.filter { $0.hasPrefix(prefix) && $0.hasSuffix(".json") && $0 != "keys.json" }.sorted()
}

/// Runs a throwing call and keeps the typed error.
func outcome<T>(_ body: () throws(OpenEntityError) -> T) -> Result<T, OpenEntityError> { Result(catching: body) }

func hex(_ d: some Sequence<UInt8>) -> String { d.map { String(format: "%02x", $0) }.joined() }

func unhex(_ s: String) -> Data {
    let b = Array(s.utf8)
    return Data(stride(from: 0, to: b.count, by: 2).map { UInt8(String(decoding: b[$0..<($0 + 2)], as: UTF8.self), radix: 16)! })
}

func b64url(_ d: Data) -> String {
    d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

// Short accessors for vector fields; a missing field reads as empty and fails the comparison that uses it.
extension JSONValue {
    var str: String { stringValue ?? "" }
    var int: Int64 { Int64(numberValue ?? -1) }
    var list: [JSONValue] { arrayValue ?? [] }
    var strings: [String] { list.map(\.str) }
    var jwk: JWK { JWK(kty: self["kty"]?.str ?? "", crv: self["crv"]?.str ?? "", x: self["x"]?.str ?? "", y: self["y"]?.str ?? "") }
    func at(_ key: String) -> JSONValue { self[key] ?? .null }
    var objectCount: Int {
        if case .object(let m) = self { return m.count }
        return 0
    }
}

/// Byte-exact comparison of two JSON values through their RFC 8785 forms.
func sameJSON(_ a: JSONValue, _ b: JSONValue) throws -> Bool {
    Array(try canonicalize(a).utf8) == Array(try canonicalize(b).utf8)
}
