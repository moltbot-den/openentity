package org.openentity.sdk

import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

private val CASES = vector("did-web-1/vectors.json")["cases"].items()
private const val ISSUER = "did:web:issuer.example"

private fun case(name: String) = CASES.first { it["name"].text() == name }

/** One did:web host behind a fake clock: it serves [document], fails while [down], and counts [fetches]. */
private class Host(var document: JsonValue) {
    var now = 0L
    var down = false
    var fetches = 0
    val resolver = DidWebResolver({ fetches++; if (down) throw IOException("host down") else document }, { now })

    /** The signer, or the error code. */
    fun verify(obj: JsonValue): String = try {
        verifyObject(obj, resolver)
    } catch (e: OpenEntityException) {
        e.code
    }
}

/** Every did-web-1 case: a fetch that serves `document` at `url` only, `expect` matched, exactly one fetch. */
@RunWith(Parameterized::class)
class DidWebVectorTest(private val name: String, private val case: JsonValue) {
    companion object {
        @JvmStatic
        @Parameterized.Parameters(name = "{0}")
        fun cases() = CASES.map { arrayOf(it["name"].text(), it) }
    }

    @Test
    fun matchesExpect() {
        var fetches = 0
        val resolver = DidWebResolver({ url -> fetches++; if (url == case["url"].text()) case["document"]!! else throw IOException("nothing at $url") })
        var message = ""
        val got = try {
            json(mapOf("ok" to true, "signer" to verifyObject(case["attestation"]!!, resolver)))
        } catch (e: OpenEntityException) {
            message = ": ${e.code}, ${e.message}"
            json(mapOf("ok" to false))
        }
        assertEquals("did-web-1 $name$message", canonicalize(case["expect"]!!), canonicalize(got))
        assertEquals("did-web-1 $name fetches", 1, fetches)
    }
}

class DidWebResolverTest {
    private val document = case("multikey-absolute-id")["document"]!!
    private val byKey1 = case("multikey-absolute-id")["attestation"]!!
    private val byKey2 = case("jsonwebkey-relative-id")["attestation"]!!
    private val byUnlistedKey = case("unlisted-key")["attestation"]!!

    private fun withMethods(change: (List<JsonValue>) -> List<JsonValue>) =
        JsonValue.Obj((document as JsonValue.Obj).fields + ("verificationMethod" to JsonValue.Arr(change(document["verificationMethod"].items()))))

    @Test
    fun keysAreCachedTenMinutesPerDid() {
        val h = Host(document)
        assertEquals(ISSUER, h.verify(byKey1))
        h.now = 599_999
        assertEquals(ISSUER, h.verify(byKey1))
        assertEquals(ISSUER, h.verify(byKey2))
        assertEquals(1, h.fetches)
        h.now = 600_000
        assertEquals(ISSUER, h.verify(byKey1))
        assertEquals(2, h.fetches)
    }

    @Test
    fun anUnknownKeyRefetchesAfterThirtySecondsSoARotationIsPickedUp() {
        val h = Host(withMethods { it.take(1) }) // key-1 only
        assertEquals(ISSUER, h.verify(byKey1))
        h.document = document // the issuer adds key-2
        h.now = 29_999
        assertEquals("bad_signature", h.verify(byKey2))
        assertEquals(1, h.fetches)
        h.now = 30_000
        assertEquals(ISSUER, h.verify(byKey2))
        assertEquals(2, h.fetches)
        h.now = 40_000
        assertEquals(ISSUER, h.verify(byKey2))
        assertEquals(2, h.fetches)
    }

    @Test
    fun badProofsFetchAtMostOnceEveryThirtySeconds() {
        val h = Host(document)
        for (t in 0L..120_000L step 5_000L) {
            h.now = t
            assertEquals("at $t", "bad_signature", h.verify(byUnlistedKey))
        }
        assertEquals(5, h.fetches) // at 0, 30, 60, 90 and 120 seconds
        h.now = 125_000
        assertEquals(ISSUER, h.verify(byKey1)) // a listed key uses the cache
        assertEquals(5, h.fetches)
    }

    @Test
    fun aFailedFetchIsRetriedAfterThirtySeconds() {
        val h = Host(document)
        h.down = true
        assertEquals("unresolved", h.verify(byKey1))
        h.down = false
        h.now = 29_999
        assertEquals("unresolved", h.verify(byKey1))
        assertEquals(1, h.fetches)
        h.now = 30_000
        assertEquals(ISSUER, h.verify(byKey1))
        assertEquals(2, h.fetches)
    }

    @Test
    fun errorCodesAndOfflineDidKey() {
        assertEquals("unresolved", Host(case("document-names-another-did")["document"]!!).verify(byKey1))
        assertEquals("bad_signature", Host(case("not-ed25519")["document"]!!).verify(case("not-ed25519")["attestation"]!!))
        assertEquals("bad_signature", Host(document).verify(case("tampered-attestation")["attestation"]!!))
        val h = Host(document).apply { down = true }
        val declaration = vector("declaration.json")["object"]!!
        assertEquals(declaration["eid"].text(), h.verify(declaration)) // did:key never fetches
        assertEquals(0, h.fetches)
        expectCode("unsupported") { verifyObject(byKey1) } // the default resolver is did:key only
    }

    @Test
    fun urlsAndKeyMaterial() {
        assertEquals("https://issuer.example/.well-known/did.json", didWebUrl(ISSUER))
        assertEquals("https://issuer.example:8443/teams/red/did.json", didWebUrl("did:web:issuer.example%3A8443:teams:red"))
        for (bad in listOf("did:web:", "did:web:evil.example%40issuer.example", "did:web:a%2Fb", "did:web:a%ZZ", "did:web:a%2", "did:web:a%C3", "did:web:a%3A1x")) {
            assertThrows(bad, OpenEntityException::class.java) { didWebUrl(bad) }
        }
        assertEquals(setOf("$ISSUER#key-1", "$ISSUER#key-2"), ed25519Methods(ISSUER, document).keys) // "#key-2" made absolute
        val paddedX = withMethods { m ->
            val jwk = m[1]["publicKeyJwk"] as JsonValue.Obj
            listOf(m[0], JsonValue.Obj((m[1] as JsonValue.Obj).fields + ("publicKeyJwk" to JsonValue.Obj(jwk.fields + ("x" to JsonValue.Str(jwk["x"].text() + "="))))))
        }
        assertEquals(setOf("$ISSUER#key-1"), ed25519Methods(ISSUER, paddedX).keys) // x must be strict base64url
        assertThrows(IOException::class.java) { fetchDidJson("http://issuer.example/.well-known/did.json") } // refused before connecting
    }
}
