// Open Entity primitives, ported from sdk/ts/src/core.ts: JSON read the way JavaScript reads it, its RFC 8785 (JCS) form,
// and eddsa-jcs-2022 proofs by did:key signers. Verify only: nothing in this SDK signs or touches the network.
package org.openentity.sdk

import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * A verification failure. [code] is the error the shared test vectors name (`malformed`, `bad_signature`, `unauthorized`, ...);
 * [seq] is the failing key log entry, null elsewhere. A bad argument (an invalid service key, a summary with a float) is the
 * caller's error and throws IllegalArgumentException instead.
 */
class OpenEntityException(val code: String, val seq: Int?, message: String) : Exception(message)

internal fun fail(code: String, message: String): Nothing = throw OpenEntityException(code, null, message)

/** A JSON value as JavaScript's JSON.parse reads it: every number is a double. */
sealed class JsonValue {
    data object Null : JsonValue()
    data class Bool(val value: Boolean) : JsonValue()
    data class Num(val value: Double) : JsonValue()
    data class Str(val value: String) : JsonValue()
    data class Arr(val items: List<JsonValue>) : JsonValue()
    data class Obj(val fields: Map<String, JsonValue>) : JsonValue()

    companion object {
        /** RFC 8259 JSON (the JSON.parse grammar) with no duplicate keys and no lone surrogates (spec 4.3). Throws IllegalArgumentException. */
        fun parse(text: String): JsonValue = Parser(text).document()
    }
}

internal operator fun JsonValue?.get(key: String): JsonValue? = (this as? JsonValue.Obj)?.fields?.get(key)
internal fun JsonValue?.str(): String? = (this as? JsonValue.Str)?.value

// ponytail: fixed nesting cap so hostile input cannot overflow the stack; real entries nest fewer than 10 levels.
private const val MAX_DEPTH = 512
private const val HEX = "0123456789abcdef"

private class Parser(private val s: String) {
    private var i = 0

    fun document(): JsonValue {
        val v = value(0)
        ws()
        if (i < s.length) bad("data after the value")
        return v
    }

    private fun bad(what: String): Nothing = throw IllegalArgumentException("invalid JSON at $i: $what")

    private fun ws() {
        while (i < s.length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++
    }

    private fun eat(c: Char): Boolean = (i < s.length && s[i] == c).also { if (it) i++ }

    private fun digits(): Boolean {
        val from = i
        while (i < s.length && s[i] in '0'..'9') i++
        return i > from
    }

    private fun value(depth: Int): JsonValue {
        if (depth > MAX_DEPTH) bad("nested more than $MAX_DEPTH levels")
        ws()
        if (i >= s.length) bad("unexpected end")
        return when (s[i]) {
            '{' -> { i++; obj(depth) }
            '[' -> { i++; arr(depth) }
            '"' -> JsonValue.Str(string())
            't' -> word("true", JsonValue.Bool(true))
            'f' -> word("false", JsonValue.Bool(false))
            'n' -> word("null", JsonValue.Null)
            else -> number()
        }
    }

    private fun obj(depth: Int): JsonValue {
        val m = LinkedHashMap<String, JsonValue>()
        ws()
        if (eat('}')) return JsonValue.Obj(m)
        do {
            ws()
            if (i >= s.length || s[i] != '"') bad("expected a key")
            val k = string()
            if (k in m) bad("duplicate key")
            ws()
            if (!eat(':')) bad("expected ':'")
            m[k] = value(depth + 1)
            ws()
        } while (eat(','))
        if (!eat('}')) bad("expected ',' or '}'")
        return JsonValue.Obj(m)
    }

    private fun arr(depth: Int): JsonValue {
        val a = ArrayList<JsonValue>()
        ws()
        if (eat(']')) return JsonValue.Arr(a)
        do {
            a += value(depth + 1)
            ws()
        } while (eat(','))
        if (!eat(']')) bad("expected ',' or ']'")
        return JsonValue.Arr(a)
    }

    private fun word(w: String, v: JsonValue): JsonValue {
        if (!s.startsWith(w, i)) bad("unexpected character")
        i += w.length
        return v
    }

    private fun number(): JsonValue {
        val start = i
        eat('-')
        if (!eat('0') && !(i < s.length && s[i] in '1'..'9' && digits())) bad("unexpected character")
        if (eat('.') && !digits()) bad("expected a digit after '.'")
        if (eat('e') || eat('E')) {
            if (!eat('+')) eat('-')
            if (!digits()) bad("expected exponent digits")
        }
        return JsonValue.Num(s.substring(start, i).toDouble()) // the grammar is checked, so this is JavaScript's double
    }

    private fun string(): String {
        i++ // the opening quote
        val b = StringBuilder()
        while (true) {
            if (i >= s.length) bad("unterminated string")
            val c = s[i++]
            when {
                c == '"' -> break
                c == '\\' -> b.append(escape())
                c < ' ' -> bad("control character in a string")
                else -> b.append(c)
            }
        }
        val out = b.toString()
        if (hasLoneSurrogate(out)) bad("lone surrogate in a string")
        return out
    }

    private fun escape(): Char {
        if (i >= s.length) bad("unterminated escape")
        return when (val e = s[i++]) {
            '"', '\\', '/' -> e
            'b' -> '\b'
            'f' -> '\u000c'
            'n' -> '\n'
            'r' -> '\r'
            't' -> '\t'
            'u' -> {
                if (i + 4 > s.length) bad("short \\u escape")
                var code = 0
                repeat(4) {
                    val h = when (val c = s[i++]) {
                        in '0'..'9' -> c - '0'
                        in 'a'..'f' -> c - 'a' + 10
                        in 'A'..'F' -> c - 'A' + 10
                        else -> bad("bad \\u escape")
                    }
                    code = code * 16 + h
                }
                Char(code)
            }
            else -> bad("bad escape")
        }
    }
}

internal fun hasLoneSurrogate(s: String): Boolean {
    var j = 0
    while (j < s.length) {
        val c = s[j]
        if (c.isHighSurrogate() && j + 1 < s.length && s[j + 1].isLowSurrogate()) j += 2
        else if (c.isSurrogate()) return true
        else j++
    }
    return false
}

/** RFC 8785 (JCS): keys sorted by UTF-16 code units, strings escaped as JSON.stringify does, numbers in ECMAScript form. NaN and infinities throw IllegalArgumentException. */
fun canonicalize(v: JsonValue): String = StringBuilder().also { jcs(v, it) }.toString()

private fun jcs(v: JsonValue, out: StringBuilder) {
    when (v) {
        JsonValue.Null -> out.append("null")
        is JsonValue.Bool -> out.append(v.value)
        is JsonValue.Num -> out.append(jcsNumber(v.value))
        is JsonValue.Str -> jcsString(v.value, out)
        is JsonValue.Arr -> {
            out.append('[')
            v.items.forEachIndexed { k, x -> if (k > 0) out.append(','); jcs(x, out) }
            out.append(']')
        }
        is JsonValue.Obj -> {
            out.append('{')
            v.fields.keys.sorted().forEachIndexed { k, key ->
                if (k > 0) out.append(',')
                jcsString(key, out)
                out.append(':')
                jcs(v.fields.getValue(key), out)
            }
            out.append('}')
        }
    }
}

private fun jcsString(s: String, out: StringBuilder) {
    out.append('"')
    var j = 0
    while (j < s.length) {
        val c = s[j]
        when {
            c == '"' -> out.append("\\\"")
            c == '\\' -> out.append("\\\\")
            c == '\b' -> out.append("\\b")
            c == '\u000c' -> out.append("\\f")
            c == '\n' -> out.append("\\n")
            c == '\r' -> out.append("\\r")
            c == '\t' -> out.append("\\t")
            c < ' ' -> out.append("\\u00").append(HEX[c.code shr 4]).append(HEX[c.code and 15])
            c.isHighSurrogate() && j + 1 < s.length && s[j + 1].isLowSurrogate() -> out.append(c).append(s[++j])
            c.isSurrogate() -> out.append("\\u").append(Integer.toHexString(c.code)) // lone, escaped as ES2019 JSON.stringify does
            else -> out.append(c)
        }
        j++
    }
    out.append('"')
}

/**
 * ECMAScript Number::toString, as RFC 8785 requires. The digits come from Double.toString, which is the shortest round-trip
 * form on JDK 19+ and for the short decimals objects carry. ponytail: Android's older Double.toString can print a longer form
 * for some 16 and 17 digit values, and subnormals below 1e-320 keep Java's two digits; such an object fails to verify, it never
 * verifies wrongly. Port a shortest-digits algorithm if one ever turns up.
 */
internal fun jcsNumber(x: Double): String {
    require(x.isFinite()) { "NaN and infinities have no JSON form" }
    if (x == 0.0) return "0" // and -0
    val t = Math.abs(x).toString() // "123.45", "1.0E21" or "1.0E-7"
    val e = t.indexOf('E')
    val mantissa = if (e < 0) t else t.substring(0, e)
    val dot = mantissa.indexOf('.')
    val all = mantissa.removeRange(dot, dot + 1)
    val lead = all.indexOfFirst { it != '0' }
    val digits = all.substring(lead).trimEnd('0')
    val n = dot + (if (e < 0) 0 else t.substring(e + 1).toInt()) - lead // the value is 0.digits times 10^n
    val k = digits.length
    val r = when {
        n in k..21 -> digits + "0".repeat(n - k)
        n in 1..21 -> digits.substring(0, n) + "." + digits.substring(n)
        n in -5..0 -> "0." + "0".repeat(-n) + digits
        else -> (if (k == 1) digits else digits[0] + "." + digits.substring(1)) + (if (n - 1 < 0) "e-" else "e+") + Math.abs(n - 1)
    }
    return if (x < 0) "-$r" else r
}

internal fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)
internal fun sha256(s: String): ByteArray = sha256(s.toByteArray())
internal fun hex(b: ByteArray): String = buildString { for (x in b) append(HEX[(x.toInt() shr 4) and 15]).append(HEX[x.toInt() and 15]) }
internal fun b64url(b: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(b)

// ---------------------------------------------------------------- did:key and eddsa-jcs-2022

private const val B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
private val DID_KEY = Regex("did:key:z([1-9A-HJ-NP-Za-km-z]+)")
private val ED25519_SPKI = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)

private fun base58(s: String): ByteArray? {
    var n = BigInteger.ZERO
    for (c in s) {
        val d = B58.indexOf(c)
        if (d < 0) return null
        n = n.multiply(BigInteger.valueOf(58)).add(BigInteger.valueOf(d.toLong()))
    }
    val body = if (n.signum() == 0) ByteArray(0) else n.toByteArray().let { if (it[0].toInt() == 0) it.copyOfRange(1, it.size) else it }
    return ByteArray(s.takeWhile { it == '1' }.length) + body
}

/** The Ed25519 key of a did:key, or null for any other DID. */
private fun didKeyEd25519(did: String): ByteArray? {
    val b = base58(DID_KEY.matchEntire(did)?.groupValues?.get(1) ?: return null) ?: return null
    return if (b.size == 34 && b[0] == 0xed.toByte() && b[1].toInt() == 1) b.copyOfRange(2, 34) else null
}

/** RFC 8032 Ed25519 through the JDK (15+) or Android 13+; an older runtime fails with `unsupported`, never with a false result. */
internal fun ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
    val (factory, verifier) = try {
        KeyFactory.getInstance("Ed25519") to Signature.getInstance("Ed25519")
    } catch (e: NoSuchAlgorithmException) {
        fail("unsupported", "this runtime has no Ed25519 (needs JDK 15+ or Android 13+)")
    }
    return try {
        verifier.initVerify(factory.generatePublic(X509EncodedKeySpec(ED25519_SPKI + publicKey)))
        verifier.update(message)
        verifier.verify(signature)
    } catch (e: GeneralSecurityException) {
        false
    }
}

/** Verifies an object's own `proof` and returns the signer's DID. Throws OpenEntityException. */
fun verifyObject(obj: JsonValue): String = verifyProof(obj, obj["proof"] ?: fail("malformed", "missing proof"))

/**
 * Verifies one eddsa-jcs-2022 proof over [obj] (a ContinuityLink carries one per key in `proofs`) and returns the signer's DID.
 * Only did:key (Ed25519) signers resolve offline. EIP-712 proofs by did:pkh signers fail with `unsupported`: the JDK has no
 * secp256k1 or keccak. Throws OpenEntityException (`malformed`, `unsupported`, `bad_signature`).
 */
fun verifyProof(obj: JsonValue, proof: JsonValue): String {
    if (obj !is JsonValue.Obj) fail("malformed", "the signed object must be a JSON object")
    if (proof !is JsonValue.Obj) fail("malformed", "missing proof")
    val method = proof["verificationMethod"].str() ?: fail("malformed", "missing proof")
    if (proof["proofPurpose"].str() != "assertionMethod") fail("malformed", "proofPurpose must be assertionMethod")
    when (proof["type"].str()) {
        "DataIntegrityProof" -> {}
        "EthereumEip712Signature2021" -> fail("unsupported", "EIP-712 proofs (did:pkh) are not in this SDK")
        else -> fail("unsupported", "unsupported proof type")
    }
    if (proof["cryptosuite"].str() != "eddsa-jcs-2022") fail("unsupported", "unsupported cryptosuite")
    val value = proof["proofValue"].str()
    if (value == null || !value.startsWith("z")) fail("malformed", "proofValue must be multibase base58btc")
    val sig = base58(value.substring(1))
    if (sig == null || sig.size != 64) fail("malformed", "proofValue must be a 64-byte signature")
    val signer = method.substringBefore('#')
    val key = didKeyEd25519(signer) ?: fail("unsupported", "only did:key Ed25519 signers resolve offline")
    // hashData: SHA-256(JCS(proof without proofValue)) || SHA-256(JCS(object without proof and proofs)).
    val message = try {
        sha256(canonicalize(JsonValue.Obj(proof.fields - "proofValue"))) + sha256(canonicalize(JsonValue.Obj(obj.fields - "proof" - "proofs")))
    } catch (e: IllegalArgumentException) {
        fail("malformed", e.message.orEmpty())
    }
    if (!ed25519Verify(key, message, sig)) fail("bad_signature", "signature does not verify")
    return signer
}
