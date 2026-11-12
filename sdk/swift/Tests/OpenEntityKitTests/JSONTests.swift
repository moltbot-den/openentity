import Foundation
import OpenEntityKit
import Testing

@Suite("JSON and RFC 8785")
struct JSONTests {
    /// ECMAScript Number::toString, the RFC 8785 number form.
    @Test(arguments: [
        (1e21, "1e+21"), (1e-7, "1e-7"), (0.000001, "0.000001"), (-0.0, "0"), (100.0, "100"), (0.81, "0.81"), (0.12, "0.12"),
        (1e20, "100000000000000000000"), (123e-20, "1.23e-18"), (5e-324, "5e-324"), (1.7976931348623157e308, "1.7976931348623157e+308"),
        (0.1 + 0.2, "0.30000000000000004"), (-1.5, "-1.5"), (9007199254740991, "9007199254740991"), (1e-6 * 1.5, "0.0000015"),
        (1.2345678901234568e20, "123456789012345680000"), (4.35, "4.35"), (1.0e16, "10000000000000000"),
    ])
    func numberForm(_ x: Double, _ want: String) throws {
        #expect(try canonicalize(.number(x)) == want)
    }

    @Test func nonFiniteNumbersHaveNoJCSForm() {
        #expect(throws: OpenEntityError.self) { try canonicalize(.number(.infinity)) }
        #expect(throws: OpenEntityError.self) { try canonicalize(.number(.nan)) }
    }

    @Test func parsedNumbersRoundLikeJSONParse() throws {
        #expect(try canonicalize(JSONValue.parse("[9007199254740993, -0, 1E2, 0.1e1, 1e400]").arrayValue!.dropLast().map { $0 }.asArray) == "[9007199254740992,0,100,1]")
        #expect(throws: OpenEntityError.self) { try canonicalize(JSONValue.parse("1e400")) }
    }

    @Test func stringsEscapeAsJSONStringify() throws {
        let v = try JSONValue.parse(#"["\u00e9\ud83d\ude00\u2028\u007f", "\u0000\u001f\b\t\n\f\r\"\\\/"]"#)
        #expect(try canonicalize(v) == "[\"\u{e9}\u{1F600}\u{2028}\u{7f}\",\"\\u0000\\u001f\\b\\t\\n\\f\\r\\\"\\\\/\"]")
    }

    @Test func keysSortByUTF16CodeUnits() throws {
        let v = try JSONValue.parse(#"{"\uff5e":1,"\ud83d\ude00":2,"z":3,"\u00e9":4,"a":5}"#)
        #expect(try canonicalize(v) == "{\"a\":5,\"z\":3,\"\u{e9}\":4,\"\u{1F600}\":2,\"\u{FF5E}\":1}")
    }

    @Test(arguments: [
        #"{"a":1,"a":2}"#, #"{"a":1,"\u0061":2}"#, #"[{"x":{"y":1,"y":1}}]"#,  // duplicate keys (spec 4.3)
        #""\ud800""#, #""\udc00""#, #""\ud800\u0041""#, #""\ud800x""#,  // lone surrogates
        "", " ", "[1,]", "{\"a\":1,}", "01", "+1", ".5", "1.", "1e", "-", "NaN", "Infinity", "'a'", "[1 2]", "{\"a\" 1}",
        "\"\t\"", "\"a", "tru", "nulls", "\u{FEFF}{}", "{}x", "\"\\x\"", "\"\\u12\"", "\"\\u+123\"", "[\"a\"]]",
    ])
    func invalidJSONIsRejected(_ text: String) {
        #expect(throws: OpenEntityError.self) { try JSONValue.parse(text) }
    }

    @Test func nestingIsCapped() throws {
        _ = try JSONValue.parse(String(repeating: "[", count: 128) + String(repeating: "]", count: 128))
        #expect(throws: OpenEntityError.self) { try JSONValue.parse(String(repeating: "[", count: 129) + String(repeating: "]", count: 129)) }
        #expect(throws: OpenEntityError.self) { try JSONValue.parse(String(repeating: "[", count: 100_000)) }
    }

    @Test func invalidUTF8IsRejected() throws {
        _ = try JSONValue.parse(Data("[\"\u{e9}\"]".utf8))
        #expect(throws: OpenEntityError.self) { try JSONValue.parse(Data([0x5B, 0x22, 0xC3, 0x22, 0x5D])) }
        #expect(throws: OpenEntityError.self) { try JSONValue.parse(Data([0x22, 0xED, 0xA0, 0x80, 0x22])) }  // UTF-8 encoded surrogate
    }
}

extension Array where Element == JSONValue {
    var asArray: JSONValue { .array(self) }
}
