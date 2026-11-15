package org.openentity.sdk

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

private val SIG = vector("http-signature.json")
private val ENTITY_DID = SIG["did"].text()

private fun strMap(v: JsonValue?) = (v as JsonValue.Obj).fields.mapValues { it.value.text() }

/** The did.json of `document` for its `url` only, and a count of fetches. */
private class Docs(private val url: String, private val doc: JsonValue) {
    var fetches = 0
    val resolver = DidWebResolver(fetch = { u -> fetches++; if (u == url) doc else throw java.io.IOException("no $u") })
}

private fun verify(c: JsonValue, now: Long, allow: List<String> = emptyList(), expect: List<String>? = null, resolver: DidWebResolver = DidWebResolver()) =
    verifyRequest(c["method"].text(), c["url"].text(), strMap(c["headers"]), c["body"].text().toByteArray(), c["now"]?.long() ?: now, allowDidWeb = allow, expectDid = expect, resolver = resolver)

private fun code(block: () -> Unit) = assertThrows(OpenEntityException::class.java, block).code

/** A signed request made the way sdk/ts and sdk/python make one: seed 1..32 is the entity throwaway seed of keys.json. */
internal fun signRequest(method: String, url: String, body: ByteArray, seed: ByteArray, did: String, created: Long): Map<String, String> {
    val out = linkedMapOf<String, String>()
    var comps = "\"@method\" \"@target-uri\""
    var digest = ""
    if (body.isNotEmpty()) {
        digest = "sha-256=:" + Base64.getEncoder().encodeToString(sha256(body)) + ":"
        out["Content-Digest"] = digest
        comps += " \"content-digest\""
    }
    val params = "($comps);created=$created;expires=${created + 60};nonce=\"AAECAwQFBgcICQoLDA0ODw\";keyid=\"$did\";alg=\"ed25519\""
    val base = "\"@method\": $method\n\"@target-uri\": $url\n" + (if (body.isNotEmpty()) "\"content-digest\": $digest\n" else "") + "\"@signature-params\": $params"
    out["Signature-Input"] = "sig1=$params"
    out["Signature"] = "sig1=:" + Base64.getEncoder().encodeToString(ed25519Sign(seed, base.toByteArray())) + ":"
    return out
}

class HttpSigTest {
    private val now = SIG["now"].long()

    @Test
    fun validVectorsVerifyToTheEntityDid() {
        for (c in SIG["valid"].items()) {
            val r = verify(c, now)
            assertEquals(c["name"].text(), ENTITY_DID, r.did)
            assertEquals(c["created"].long(), r.created)
            assertEquals(c["nonce"].text(), r.nonce)
        }
    }

    @Test
    fun invalidVectorsFailWithTheirCode() {
        for (c in SIG["invalid"].items()) assertEquals(c["name"].text(), c["code"].text(), code { verify(c, now) })
    }

    @Test
    fun didWebKeyidsVerifyOnlyForAnAllowedDidAndAnAuthenticationKey() {
        val d = SIG["did_web"]!!
        val did = d["did"].text()
        for (c in d["valid"].items()) {
            val docs = Docs(d["url"].text(), d["document"]!!)
            assertEquals(c["name"].text(), did, verify(c, d["now"].long(), allow = listOf(did), resolver = docs.resolver).did)
        }
        for (c in d["invalid"].items()) {
            val docs = Docs(d["url"].text(), d["document"]!!)
            val allow = if (c["name"].text() == "did-not-allowed") emptyList() else listOf(did)
            assertEquals(c["name"].text(), c["code"].text(), code { verify(c, d["now"].long(), allow = allow, resolver = docs.resolver) })
        }
    }

    @Test
    fun theSignerPinRefusesBeforeAnyFetch() {
        val e = SIG["expect_did"]!!
        for (c in e["requests"]["valid"].items()) {
            val docs = Docs(e["url"].text(), e["document"]!!)
            assertEquals(c["name"].text(), c["did"].text(), verify(c, e["now"].long(), expect = pin(c), resolver = docs.resolver).did)
        }
        for (c in e["requests"]["invalid"].items()) {
            val docs = Docs(e["url"].text(), e["document"]!!)
            assertEquals(c["name"].text(), c["code"].text(), code { verify(c, e["now"].long(), expect = pin(c), resolver = docs.resolver) })
            assertEquals(c["name"].text(), 0, docs.fetches)
        }
    }

    @Test
    fun allowDidWebAloneIsNotAPin() {
        val e = SIG["expect_did"]!!
        val c = e["requests"]["invalid"].items().first { it["name"].text() == "did-key-under-did-web-pin" }
        assertTrue(verify(c, e["now"].long(), allow = pin(c)).did.startsWith("did:key:"))
    }

    @Test
    fun aDidKeyKeyidMustBeTheCanonicalSpelling() {
        val c = SIG["valid"].items()[1]
        val h = strMap(c["headers"]).mapValues { it.value.replace(ENTITY_DID, ENTITY_DID + "x") }
        assertEquals("bad_keyid", code { verifyRequest("GET", c["url"].text(), h, now = now) })
    }

    @Test
    fun headerNamesAreCaseInsensitiveAndAMethodIsUppercased() {
        val c = SIG["valid"].items()[1]
        val h = strMap(c["headers"]).mapKeys { it.key.uppercase() }
        assertEquals(ENTITY_DID, verifyRequest("get", c["url"].text(), h, now = now).did)
    }

    private fun pin(c: JsonValue) = (c["expect_did"] as? JsonValue.Str)?.let { listOf(it.value) } ?: c["expect_did"].items().map { it.text() }
}
