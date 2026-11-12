// did:web signers for proofs, ported from didWebResolver (sdk/ts/src/registry.ts) and ed25519Methods (sdk/ts/src/httpsig.ts),
// with the cache rules of test-vectors/did-web-1/README.md. The fetch is injectable; the default is HTTPS through HttpURLConnection.
package org.openentity.sdk

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException

private const val CACHE_MS = 600_000L // a document's keys are kept ten minutes per DID
private const val REFETCH_MS = 30_000L // and fetched again at most this often
private const val TIMEOUT_MS = 5_000
private const val DEADLINE_NS = 10_000_000_000L
private const val MAX_DOCUMENT = 256 * 1024
private val HOST = Regex("[A-Za-z0-9.-]+(:[0-9]{1,5})?")

/**
 * Resolves did:web signers through `https://<host>/.well-known/did.json` (or `<path>/did.json` for a DID with a path), and
 * did:key signers offline. A document's Ed25519 keys are cached ten minutes per DID. A proof naming a method the cached keys
 * lack refetches, at most once every 30 seconds per DID, so a rotated key is picked up without a stream of bad proofs turning
 * into a stream of fetches; a failed fetch is retried after 30 seconds too. Keep one instance: the cache lives in it.
 *
 * [fetch] returns the parsed document at a URL or throws. The default is HTTPS only, 5-second timeouts, no redirects and at
 * most 256 KiB; it blocks, so verify off the main thread. Resolve only issuers you accept: verifying an object fetches from
 * the host its signer names. [clock] is milliseconds from any fixed point (monotonic by default).
 */
class DidWebResolver(
    private val fetch: (url: String) -> JsonValue = ::fetchDidJson,
    private val clock: () -> Long = { System.nanoTime() / 1_000_000 },
) : Resolver {
    private class Fetched(val at: Long, val keys: Map<String, ByteArray>?, val error: String?)

    private val cache = HashMap<String, Fetched>()

    // ponytail: one lock for every DID, so a slow fetch holds up other issuers; per-DID locks if an app resolves many at once.
    @Synchronized
    override fun ed25519Keys(verificationMethod: String): List<ByteArray> {
        val did = verificationMethod.substringBefore('#')
        if (!did.startsWith("did:web:")) return Resolver.DID_KEY.ed25519Keys(verificationMethod)
        val now = clock()
        val hit = cache[did]
        val age = if (hit == null) Long.MAX_VALUE else now - hit.at
        val keys = hit?.keys
        val fresh = when {
            hit == null -> false
            keys == null -> age < REFETCH_MS
            else -> age < CACHE_MS && (verificationMethod in keys || age < REFETCH_MS)
        }
        val entry = if (fresh) hit!! else load(did, now).also { cache[did] = it }
        return entry.keys?.values?.toList() ?: fail("unresolved", entry.error.orEmpty())
    }

    private fun load(did: String, now: Long): Fetched = try {
        Fetched(now, ed25519Methods(did, fetch(didWebUrl(did))), null)
    } catch (e: OpenEntityException) {
        Fetched(now, null, e.message)
    } catch (e: Exception) {
        Fetched(now, null, "cannot fetch the document of $did: $e")
    }
}

/** The did.json URL of a did:web DID. Each `:`-separated part is percent-decoded; the first is the host, with a port as `%3A`. */
internal fun didWebUrl(did: String): String {
    val parts = did.removePrefix("did:web:").split(':').map { percentDecode(it) ?: fail("unresolved", "$did is not percent-encoded correctly") }
    if (!HOST.matches(parts[0])) fail("unresolved", "$did does not name a host")
    return "https://${parts[0]}/${if (parts.size > 1) parts.drop(1).joinToString("/") else ".well-known"}/did.json"
}

/** decodeURIComponent: `%XX` sequences to bytes read as UTF-8; null for a malformed sequence. */
private fun percentDecode(s: String): String? {
    val out = ByteArrayOutputStream()
    var i = 0
    while (i < s.length) {
        val j = s.indexOf('%', i).let { if (it < 0) s.length else it }
        out.write(s.substring(i, j).toByteArray())
        if (j == s.length) break
        if (j + 2 >= s.length) return null
        val hi = hexValue(s[j + 1])
        val lo = hexValue(s[j + 2])
        if (hi < 0 || lo < 0) return null
        out.write(hi * 16 + lo)
        i = j + 3
    }
    return utf8(out.toByteArray())
}

/** Strict UTF-8 (newDecoder() rejects malformed input), or null. */
private fun utf8(b: ByteArray): String? = try {
    Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(b)).toString()
} catch (e: CharacterCodingException) {
    null
}

/**
 * Ed25519 keys of a DID document by absolute method id (`#key-1` is relative to the DID): a `publicKeyMultibase` that is an
 * Ed25519 multikey, or a `publicKeyJwk` with kty OKP, crv Ed25519 and a strict base64url `x`. Any other key yields nothing. A
 * document whose `id` is not [did] fails `unresolved`.
 */
internal fun ed25519Methods(did: String, doc: JsonValue): Map<String, ByteArray> {
    if (doc["id"].str() != did) fail("unresolved", "the document for $did names ${doc["id"].str()}")
    val keys = LinkedHashMap<String, ByteArray>()
    for (vm in (doc["verificationMethod"] as? JsonValue.Arr)?.items.orEmpty()) {
        val id = vm["id"].str()?.let { if (it.startsWith("#")) did + it else it } ?: continue
        val multibase = vm["publicKeyMultibase"]
        val jwk = vm["publicKeyJwk"]
        val key = when {
            multibase is JsonValue.Str -> didKeyEd25519("did:key:" + multibase.value)
            jwk["kty"].str() == "OKP" && jwk["crv"].str() == "Ed25519" -> b64u(jwk["x"].str())
            else -> null
        }
        if (key != null && key.size == 32) keys[id] = key
    }
    return keys
}

/** The default fetch: HTTPS GET, 5-second connect and read timeouts, 10 seconds in all, no redirects, at most 256 KiB of strict JSON. */
internal fun fetchDidJson(url: String): JsonValue {
    val uri = URI(url)
    if (uri.scheme != "https" || uri.rawUserInfo != null) throw IOException("a DID document is fetched over HTTPS only, not $url")
    val start = System.nanoTime()
    val c = uri.toURL().openConnection() as HttpURLConnection
    try {
        c.instanceFollowRedirects = false
        c.connectTimeout = TIMEOUT_MS
        c.readTimeout = TIMEOUT_MS
        c.setRequestProperty("Accept", "application/did+json, application/json")
        if (c.responseCode !in 200..299) throw IOException("$url answered ${c.responseCode}")
        val body = ByteArrayOutputStream()
        c.inputStream.use { input ->
            val buf = ByteArray(8192)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                body.write(buf, 0, n)
                if (body.size() > MAX_DOCUMENT) throw IOException("$url is larger than $MAX_DOCUMENT bytes")
                if (System.nanoTime() - start > DEADLINE_NS) throw IOException("$url took more than 10 seconds")
            }
        }
        return JsonValue.parse(utf8(body.toByteArray()) ?: throw IOException("$url is not UTF-8"))
    } finally {
        c.disconnect()
    }
}
