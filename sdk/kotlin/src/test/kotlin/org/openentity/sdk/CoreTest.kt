package org.openentity.sdk

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

// The shared vectors at the repo root (build.gradle.kts passes the path). http-signature.json is the server-side RFC 9421
// profile, which this verify-only SDK does not carry.
internal val VECTORS = File(System.getProperty("vectors") ?: "../../test-vectors")
internal fun vector(path: String): JsonValue = JsonValue.parse(File(VECTORS, path).readText())
internal fun unhex(h: String) = ByteArray(h.length / 2) { h.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
internal fun JsonValue?.items(): List<JsonValue> = (this as JsonValue.Arr).items
internal fun JsonValue?.long(): Long = (this as JsonValue.Num).value.toLong()
internal fun JsonValue?.text(): String = (this as JsonValue.Str).value

/** Kotlin values to JSON, for comparing results with a vector's `expect`. */
internal fun json(v: Any?): JsonValue = when (v) {
    null -> JsonValue.Null
    is JsonValue -> v
    is Boolean -> JsonValue.Bool(v)
    is Number -> JsonValue.Num(v.toDouble())
    is String -> JsonValue.Str(v)
    is List<*> -> JsonValue.Arr(v.map(::json))
    is Map<*, *> -> JsonValue.Obj(v.entries.associate { (k, x) -> k as String to json(x) })
    else -> error("not JSON: $v")
}

internal fun expectCode(code: String, block: () -> Unit) = assertEquals(code, assertThrows(OpenEntityException::class.java) { block() }.code)

class CoreTest {
    @Test
    fun jcsNumbersFollowEcmaScript() {
        val cases = listOf(
            1e21 to "1e+21", 1e-7 to "1e-7", 0.000001 to "0.000001", -0.0 to "0", 100.0 to "100", 0.81 to "0.81", 0.12 to "0.12",
            1.5 to "1.5", -1.5e-7 to "-1.5e-7", 1e20 to "100000000000000000000", 123456789012345680000.0 to "123456789012345680000",
            9007199254740991.0 to "9007199254740991", 0.1 + 0.2 to "0.30000000000000004", 1794017100.0 to "1794017100",
            0.001 to "0.001", 1234567.0 to "1234567", 1e7 to "10000000", 5e-7 to "5e-7", 1.7976931348623157e308 to "1.7976931348623157e+308",
        )
        for ((x, s) in cases) assertEquals("$x", s, canonicalize(JsonValue.Num(x)))
        for (x in listOf(Double.NaN, Double.POSITIVE_INFINITY)) assertThrows(IllegalArgumentException::class.java) { canonicalize(JsonValue.Num(x)) }
    }

    @Test
    fun jcsSortsKeysByUtf16AndEscapesLikeJsonStringify() {
        assertEquals("""{"a":[true,null,"x"],"b":1,"c":{"y":2,"z":1}}""", canonicalize(JsonValue.parse("""{"b":1,"a":[true,null,"x"],"c":{"z":1,"y":2}}""")))
        assertEquals("{\"\\r\":2,\"1\":3,\"\u20ac\":1}", canonicalize(JsonValue.parse("""{"\u20ac":1,"\r":2,"1":3}""")))
        assertEquals("{\"s\":\"\\u0007\\\"\\\\/\u00e9\"}", canonicalize(JsonValue.parse("""{"s":"\u0007\"\\\/\u00e9"}""")))
        assertEquals("\"\\ud800\"", canonicalize(JsonValue.Str("\ud800"))) // built by hand: the parser never yields one
    }

    @Test
    fun parserIsStrict() {
        val bad = listOf(
            """{"a":1,"a":2}""", """{"x":{"k":1,"\u006b":2}}""", """[{"a":1,"b":{"c":1,"c":1}}]""", "\"\\ud800\"", "\"\\udc00x\"",
            "\"\ud800\"", "\"\\ud800\\u0041\"", "01", "+1", ".5", "1.", "1e", "-", "[1,]", "{\"a\":1,}", "'a'", "\"a\u0001\"", "nul",
            "[1] 2", "\ufeff{}", "\"\\x\"", "\"\\u12G4\"", "\"\\u-123\"", "NaN", "Infinity", "", " ", "[".repeat(600) + "]".repeat(600),
        )
        for (s in bad) assertThrows(s, IllegalArgumentException::class.java) { JsonValue.parse(s) }
        assertEquals(JsonValue.Str("\ud83d\ude00"), JsonValue.parse("\"\\ud83d\\ude00\""))
        assertEquals(JsonValue.Num(-0.0), JsonValue.parse(" -0 "))
        assertEquals(JsonValue.Num(Double.POSITIVE_INFINITY), JsonValue.parse("1e400")) // as JSON.parse; canonicalize refuses it
        val ok = JsonValue.parse("""{"a":1,"b":{"a":2},"c":[{"a":1},{"a":2}],"d":"a\":1"}""")
        assertEquals("""{"a":1,"b":{"a":2},"c":[{"a":1},{"a":2}],"d":"a\":1"}""", canonicalize(ok))
    }

    @Test
    fun signedVectorsCanonicalizeHashAndVerify() {
        val keys = vector("keys.json")
        val ids = listOf(keys["entity"]["eid"].text(), keys["second"]["eid"].text())
        for (name in listOf(
            "declaration", "entity-document", "record-1", "record-2", "attestation",
            "claim-liveness", "claim-endpoint-reliability", "claim-vision-privacy", "claim-gateway-governed",
        )) {
            val v = vector("$name.json")
            val obj = v["object"] as JsonValue.Obj
            assertEquals(name, v["canonical"].text(), canonicalize(obj))
            assertEquals(name, v["sha256"].text(), hex(sha256(canonicalize(obj))))
            assertEquals(name, v["unsigned_canonical"].text(), canonicalize(JsonValue.Obj(obj.fields - "proof")))
            val signer = (obj["eid"] ?: obj["issuer"]).text()
            assertTrue(name, signer in ids)
            assertEquals(name, signer, verifyObject(obj))
        }
        val link = vector("continuity-link.json")
        assertEquals(link["canonical"].text(), canonicalize(link["object"]!!))
        assertEquals(ids, link["object"]["proofs"].items().map { verifyProof(link["object"]!!, it) })
        val rotation = vector("rotation.json")["request"]
        assertEquals(ids, rotation["link"]["proofs"].items().map { verifyProof(rotation["link"]!!, it) })
        assertEquals(ids[1], verifyObject(rotation["document"]!!))
    }

    @Test
    fun tamperedOrUnsupportedProofsFail() {
        val att = vector("attestation.json")["object"] as JsonValue.Obj
        val proof = att["proof"] as JsonValue.Obj
        fun withProof(change: Pair<String, JsonValue>) = JsonValue.Obj(att.fields + ("proof" to JsonValue.Obj(proof.fields + change)))
        expectCode("bad_signature") { verifyObject(JsonValue.Obj(att.fields + ("confidence" to JsonValue.Num(0.82)))) }
        expectCode("bad_signature") { verifyObject(withProof("created" to JsonValue.Str("2026-10-24T19:05:01Z"))) }
        expectCode("bad_signature") { verifyObject(withProof("verificationMethod" to vector("record-1.json")["object"]["proof"]["verificationMethod"]!!)) }
        expectCode("malformed") { verifyObject(withProof("proofPurpose" to JsonValue.Str("authentication"))) }
        expectCode("unsupported") { verifyObject(withProof("cryptosuite" to JsonValue.Str("eddsa-rdfc-2022"))) }
        expectCode("unsupported") { verifyObject(withProof("type" to JsonValue.Str("EthereumEip712Signature2021"))) }
        expectCode("unsupported") { verifyObject(withProof("verificationMethod" to JsonValue.Str("did:web:example.com#k"))) }
        expectCode("malformed") { verifyObject(JsonValue.Obj(att.fields - "proof")) }
        val link = vector("continuity-link.json")["object"] as JsonValue.Obj
        expectCode("bad_signature") { verifyProof(JsonValue.Obj(link.fields + ("basis" to JsonValue.Str("migration"))), link["proofs"].items()[0]) }
    }

    @Test
    fun checkpointNoteAndInclusionProofs() {
        val keys = vector("keys.json")
        val cp = vector("checkpoint.json")
        val logKey = unhex(keys["log"]["publicKeyHex"].text())
        val note = cp["note"].text()
        assertTrue(verifyNote(note, "openentity.org/log", logKey))
        assertFalse(verifyNote(note.replace("\n6\n", "\n7\n"), "openentity.org/log", logKey))
        assertFalse(verifyNote(note, "other.org/log", logKey))
        assertFalse(verifyNote(note, "openentity.org/log", unhex(keys["entity"]["publicKeyHex"].text()))) // wrong key
        assertFalse(verifyNote(cp["body"].text(), "openentity.org/log", logKey))
        val size = cp["tree_size"].long()
        val root = unhex(cp["root_hash"].text())
        for (i in 0 until size) {
            val leaf = vector("log-leaf-$i.json")
            assertEquals(leaf["canonical"].text(), canonicalize(leaf["object"]!!))
            val hash = leafHash(leaf["canonical"].text().toByteArray())
            assertEquals("leaf $i", leaf["leaf_hash"].text(), hex(hash))
            val proof = cp["inclusion_proofs"].items()[i.toInt()].items().map { unhex(it.text()) }
            assertTrue("leaf $i", verifyInclusion(i, size, hash, proof, root))
            assertFalse(verifyInclusion(i, size, hash.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }, proof, root))
            assertFalse(verifyInclusion((i + 1) % size, size, hash, proof, root))
            assertFalse(verifyInclusion(size, size, hash, proof, root))
        }
    }

    @Test
    fun inclusionMatchesAnIndependentRfc9162PathForEverySizeTo40() {
        val leaves = List(40) { leafHash(byteArrayOf(it.toByte())) }
        fun h(vararg parts: ByteArray) = sha256(parts.fold(ByteArray(0)) { a, b -> a + b })
        fun k(n: Int) = Integer.highestOneBit(n - 1) // largest power of two below n
        fun mth(lo: Int, hi: Int): ByteArray = if (hi - lo == 1) leaves[lo] else h(byteArrayOf(1), mth(lo, lo + k(hi - lo)), mth(lo + k(hi - lo), hi))
        fun path(m: Int, lo: Int, hi: Int): List<ByteArray> {
            if (hi - lo == 1) return emptyList()
            val s = k(hi - lo)
            return if (m < s) path(m, lo, lo + s) + listOf(mth(lo + s, hi)) else path(m - s, lo + s, hi) + listOf(mth(lo, lo + s))
        }
        for (n in 1..40) {
            val root = mth(0, n)
            for (m in 0 until n) {
                val p = path(m, 0, n)
                assertTrue("$m of $n", verifyInclusion(m.toLong(), n.toLong(), leaves[m], p, root))
                assertFalse(verifyInclusion(m.toLong(), n.toLong(), leaves[(m + 1) % 40], p, root))
                if (p.isNotEmpty()) assertFalse(verifyInclusion(m.toLong(), n.toLong(), leaves[m], p.drop(1), root))
            }
        }
    }
}
