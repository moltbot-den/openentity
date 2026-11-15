// RFC 9421 HTTP message signatures, Open Entity profile (spec 11.2, Web Bot Auth): ported from verify_request in
// sdk/python/openentity/httpsig.py and verifyRequest in sdk/ts/src/httpsig.ts. Same checks in the same order, same error codes.
package org.openentity.sdk

import java.util.Base64

/** A verified request signature. [did] is the signer: the only trustworthy agent identity of the request. */
data class SignedRequest(val did: String, val keyid: String, val created: Long, val expires: Long, val nonce: String)

private const val SKEW = 5L // seconds of clock skew allowed on `created`
private val SIG1_MEMBER = Regex("(?:^|,)\\s*sig1=")
private val SIG1_INPUT = Regex("(?:^|,)\\s*sig1=(\\(([^)]*)\\)((?:;[a-z]+=(?:[0-9]+|\"[^\"]*\"))*))")
private val SIG1_SIGNATURE = Regex("(?:^|,)\\s*sig1=:([A-Za-z0-9+/]+={0,2}):")
private val PARAM = Regex(";([a-z]+)=([0-9]+|\"[^\"]*\")")
private val QUOTED = Regex("\"([^\"]*)\"")
private val DID_WEB_KEYID = Regex("did:web:[^#]+#[^#]+")

private fun sigFail(code: String): Nothing = fail(code, "the request signature is not valid: $code")

private fun digestOf(body: ByteArray) = "sha-256=:" + Base64.getEncoder().encodeToString(sha256(body)) + ":"

/**
 * Verifies a request signed by an Open Entity agent: ed25519, label `sig1`, covered `"@method" "@target-uri"` and, for a body,
 * `"content-digest"` (RFC 9530), `keyid` the signer's did:key, or a `did:web:<host>#<key>` of a DID in [expectDid] or [allowDidWeb]
 * (an Ed25519 method under `authentication` in its did.json, fetched through [resolver]). Throws `OpenEntityException` whose `code`
 * is the vector code (`bad_signature`, `digest_mismatch`, `expired`, ...). [headers] is any map; names are matched case-insensitively.
 * [now] is unix seconds. Nonce replay tracking is yours.
 *
 * [expectDid] pins the signer: any other keyid, a did:key included, fails `unexpected_signer` before a key is read. Pass it whenever
 * only known services may call; [allowDidWeb] alone only lets those DIDs be resolved. [resolver] blocks on a did:web fetch.
 */
fun verifyRequest(
    method: String,
    url: String,
    headers: Map<String, String>,
    body: ByteArray = ByteArray(0),
    now: Long,
    maxAge: Long = 300,
    allowDidWeb: Collection<String> = emptyList(),
    expectDid: Collection<String>? = null,
    resolver: DidWebResolver = DidWebResolver(),
): SignedRequest {
    val h = headers.mapKeys { it.key.lowercase() }
    val si = h["signature-input"].orEmpty()
    val sg = h["signature"].orEmpty()
    if (SIG1_MEMBER.findAll(si).count() != 1 || SIG1_MEMBER.findAll(sg).count() != 1) sigFail("missing_headers")
    val m = SIG1_INPUT.find(si) ?: sigFail("missing_headers")
    val sig = SIG1_SIGNATURE.find(sg)?.groupValues?.get(1) ?: sigFail("missing_headers")
    val pairs = PARAM.findAll(m.groupValues[3]).map { it.groupValues[1] to it.groupValues[2] }.toList()
    if (pairs.map { it.first }.toSet().size != pairs.size) sigFail("missing_headers")
    val p = pairs.toMap().mapValues { (_, v) -> if (v.startsWith("\"")) v.substring(1, v.length - 1) else v }
    val quoted = pairs.filter { it.second.startsWith("\"") }.map { it.first }.toSet()
    if (p["alg"] != "ed25519" || "alg" !in quoted) sigFail("unknown_alg")
    val params = m.groupValues[1]
    val comps = QUOTED.findAll(m.groupValues[2]).map { it.groupValues[1] }.toList()

    val keyid = p["keyid"].takeIf { "keyid" in quoted }.orEmpty()
    val did = keyid.substringBefore('#')
    if (expectDid != null && did !in expectDid) sigFail("unexpected_signer")
    var key: ByteArray? = null
    if (keyid.startsWith("did:web:")) {
        if (!DID_WEB_KEYID.matches(keyid) || did !in (allowDidWeb + (expectDid ?: emptyList()))) sigFail("bad_keyid")
    } else {
        key = didKeyEd25519(keyid)
        if (key == null || "did:key:z" + base58Encode(byteArrayOf(0xed.toByte(), 1) + key) != keyid) sigFail("bad_keyid")
    }
    val created = p["created"].takeIf { "created" !in quoted }?.toLongOrNull()
    val expires = p["expires"].takeIf { "expires" !in quoted }?.toLongOrNull()
    if (created == null || expires == null) sigFail("missing_headers")
    val nonce = p["nonce"].takeIf { "nonce" in quoted }.orEmpty()
    if (nonce.length < 22) sigFail("missing_nonce") // 16 bytes in base64url
    if (comps.take(2) != listOf("@method", "@target-uri") || comps.drop(2) !in listOf(emptyList(), listOf("content-digest"))) sigFail("missing_headers")
    var digest: String? = null
    if (body.isNotEmpty() || "content-digest" in comps) {
        digest = h["content-digest"]
        if ("content-digest" !in comps || digest != digestOf(body)) sigFail("digest_mismatch")
    }
    if (created > now + SKEW) sigFail("created_in_future")
    if (now - created > maxAge) sigFail("created_too_old")
    if (expires < now) sigFail("expired")
    if (expires - created > maxAge) sigFail("lifetime_too_long")
    if (key == null) key = try { resolver.authenticationKey(keyid) } catch (e: Exception) { null } ?: sigFail("bad_keyid")
    val base = buildString {
        for (c in comps) append('"').append(c).append("\": ").append(when (c) { "@method" -> method.uppercase(); "@target-uri" -> url; else -> digest }).append('\n')
        append("\"@signature-params\": ").append(params)
    }
    val raw = try { Base64.getDecoder().decode(sig) } catch (e: IllegalArgumentException) { sigFail("bad_signature") }
    if (!ed25519Verify(key, base.toByteArray(), raw)) sigFail("bad_signature")
    return SignedRequest(did, keyid, created, expires, nonce)
}
