package org.openentity.sdk

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

private val A = vector("approval-2.0/vectors.json")
private val KEYLOGS = File(VECTORS, "keylog-1").list()!!.filter { it.endsWith(".json") && it != "keys.json" }.sorted()

private fun strings(v: JsonValue?) = v.items().map { it.text() }

private fun ownerKeys(s: JsonValue) = object : OwnerKeys {
    override val did = s["did"].text()
    override val root = s["root"]?.let { Credential.fromJson(it) }
    override val approvers = s["approvers"].items().map { Credential.fromJson(it) }
    override val closed = s["closed"] == JsonValue.Bool(true)
}

/** Every keylog-1 case: the state (kids for root and approvers) or the error code and seq, exactly as `expect` says. */
@RunWith(Parameterized::class)
class KeyLogVectorTest(private val file: String) {
    companion object {
        @JvmStatic
        @Parameterized.Parameters(name = "{0}")
        fun files() = KEYLOGS
    }

    @Test
    fun matchesExpect() {
        val v = vector("keylog-1/$file")
        var message = ""
        val got = try {
            val s = verifyKeyLog(
                v["did"].text(), strings(v["log"]), v["first_seen_at"].items().map { it.long() }, v["now"].long(),
                v["service_keys"].items().map { Jwk.fromJson(it)!! }, strings(v["origins"]),
            )
            json(mapOf("ok" to true, "state" to mapOf(
                "did" to s.did, "seq" to s.seq, "head" to s.head, "root" to s.root.kid, "approvers" to s.approvers.map { it.kid },
                "revoked" to s.revoked.map { mapOf("kid" to it.kid, "at" to it.at) },
                "pending" to s.pending.map { mapOf("seq" to it.seq, "op" to it.op, "hash" to it.hash, "effective_at" to it.effectiveAt) },
                "closed" to s.closed,
            )))
        } catch (e: OpenEntityException) {
            message = ": ${e.message}"
            json(mapOf("ok" to false, "error" to e.code, "seq" to e.seq))
        }
        assertEquals("keylog-1/$file$message", canonicalize(v["expect"]!!), canonicalize(got))
    }
}

/** Every approval-2.0 case against `key_states[context.key_state]`. */
@RunWith(Parameterized::class)
class ApprovalVectorTest(private val name: String, private val case: JsonValue) {
    companion object {
        @JvmStatic
        @Parameterized.Parameters(name = "{0}")
        fun cases() = A["cases"].items().map { arrayOf(it["name"].text(), it) }
    }

    @Test
    fun matchesExpect() {
        val x = case["context"]
        var message = ""
        val got = try {
            val ok = verifyApproval(
                case["approval"]!!, ownerKeys(A["key_states"][x["key_state"].text()]!!), x["verifier_did"].text(), x["owner_did"].text(),
                x["request_id"].text(), x["payload_digest"].text(), x["now"].long(),
                decisions = x["decisions"]?.let { strings(it) } ?: listOf("approve", "deny"),
                origins = x["origins"]?.let { strings(it) },
                counter = x["counter"]?.long() ?: 0L,
                allowRoot = x["allow_root"] == JsonValue.Bool(true),
            )
            json(mapOf("ok" to true, "kid" to ok.kid, "counter" to ok.counter))
        } catch (e: OpenEntityException) {
            message = ": ${e.message}"
            json(mapOf("ok" to false, "error" to e.code))
        }
        assertEquals("approval-2.0 $name$message", canonicalize(case["expect"]!!), canonicalize(got))
    }
}

class OwnerTest {
    @Test
    fun everyKeyLogRuleHasAVector() = assertTrue(KEYLOGS.size >= 50)

    @Test
    fun didIsBase32OfTheGenesisLine() {
        val v = vector("keylog-1/genesis-device.json")
        val bits = sha256(strings(v["log"])[0]).joinToString("") { (it.toInt() and 0xff).toString(2).padStart(8, '0') }
        val suffix = bits.chunked(5).joinToString("") { "abcdefghijklmnopqrstuvwxyz234567"[it.padEnd(5, '0').toInt(2)].toString() }
        assertEquals("did:web:account.openentity.org:o:$suffix", v["did"].text())
    }

    @Test
    fun badInputIsInputNotALogFailure() {
        val v = vector("keylog-1/genesis-device.json")
        val log = strings(v["log"])
        val seen = v["first_seen_at"].items().map { it.long() }
        val now = v["now"].long()
        expectCode("bad_first_seen") { verifyKeyLog(v["did"].text(), log, emptyList(), now) }
        expectCode("bad_first_seen") { verifyKeyLog(v["did"].text(), log, seen, seen[0] - 1) }
        expectCode("malformed") { verifyKeyLog(v["did"].text(), emptyList(), emptyList(), now) }
        assertThrows(IllegalArgumentException::class.java) { verifyKeyLog(v["did"].text(), log, seen, now, listOf(Jwk("EC", "P-256", "AA", "AA"))) }
        // A boolean is never the integer 1.
        val genesis = JsonValue.parse(log[0]) as JsonValue.Obj
        val line = canonicalize(JsonValue.Obj(genesis.fields + ("v" to JsonValue.Bool(true))))
        expectCode("malformed") { verifyKeyLog(v["did"].text(), listOf(line), seen, now) }
    }

    @Test
    fun digestsForBothDecisions() {
        assertEquals(listOf("approve", "deny"), A["digests"].items().map { it["fields"]["decision"].text() })
        for (d in A["digests"].items()) {
            val f = d["fields"]
            val args = listOf("verifier_did", "owner_did", "request_id", "payload_digest", "decision").map { f[it].text() }
            assertEquals(d["preimage"].text(), approvalPreimage(args[0], args[1], args[2], args[3], args[4], f["expires_at"].long()))
            assertEquals(d["digest"].text(), hex(sha256(d["preimage"].text())))
            assertEquals(d["digest"].text(), hex(approvalDigest(args[0], args[1], args[2], args[3], args[4], f["expires_at"].long())))
            for (bad in listOf(
                args.toMutableList().also { it[2] = "a|b" }, args.toMutableList().also { it[2] = "a\n" },
                args.toMutableList().also { it[1] = "did:web:x|y" }, args.toMutableList().also { it[3] = it[3].uppercase() },
                args.toMutableList().also { it[4] = "maybe" },
            )) assertThrows(bad.toString(), IllegalArgumentException::class.java) { approvalDigest(bad[0], bad[1], bad[2], bad[3], bad[4], f["expires_at"].long()) }
            assertThrows(IllegalArgumentException::class.java) { approvalDigest(args[0], args[1], args[2], args[3], args[4], -1) }
        }
    }

    @Test
    fun payloadDigestsAreSha256OfJcsAndRefuseFloatsAndBigIntegers() {
        for (p in A["payloads"].items()) {
            assertEquals(p["canonical"].text(), canonicalize(p["summary"]!!))
            assertEquals(p["digest"].text(), payloadDigest(p["summary"]!!))
        }
        for (p in A["payloads_invalid"].items()) assertThrows(p["reason"].text(), IllegalArgumentException::class.java) { payloadDigest(p["summary"]!!) }
        assertThrows(IllegalArgumentException::class.java) { payloadDigest(JsonValue.Arr(listOf(JsonValue.Str("\ud800")))) }
    }

    @Test
    fun eachKeyStateIsWhatItsKeyLogGives() {
        val service = Jwk.fromJson(vector("approval-2.0/keys.json")["keys"]["service"]["jwk"])!!
        val ctx = A["cases"].items()[0]["context"]
        val states = A["key_states"] as JsonValue.Obj
        assertEquals(states.fields.keys, (A["key_logs"] as JsonValue.Obj).fields.keys)
        for ((name, l) in (A["key_logs"] as JsonValue.Obj).fields) {
            val s = verifyKeyLog(l["did"].text(), strings(l["log"]), l["first_seen_at"].items().map { it.long() }, ctx["now"].long(), listOf(service), strings(ctx["origins"]))
            assertEquals(name, canonicalize(states.fields.getValue(name)), canonicalize(json(mapOf("did" to s.did, "root" to s.root.json, "approvers" to s.approvers.map { it.json }, "closed" to s.closed))))
        }
    }
}
