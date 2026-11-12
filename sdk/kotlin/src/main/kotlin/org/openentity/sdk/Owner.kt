// Owner key logs (keylog-1, ADR 0007) and approval/2.0 (ADR 0008), ported from sdk/ts/src/owner.ts: same checks, same order,
// same error codes. Verify only: devices and passkeys sign, products and the app verify. The byte-level rules are in
// test-vectors/keylog-1/README.md and test-vectors/approval-2.0/README.md; OwnerTest runs both vector sets, as the other SDKs do.
package org.openentity.sdk

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.security.AlgorithmParameters
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64

private const val RP_ID = "account.openentity.org"
private const val DAY = 86_400L
private const val WEEK = 7 * DAY
private const val MAX_TTL = 600L
private const val MAX_SAFE = 9_007_199_254_740_991L // 2^53 - 1
private val REQUEST_ID = Regex("[A-Za-z0-9:._-]{1,128}")
private val HEX64 = Regex("[0-9a-f]{64}")
private val DID = Regex("did:[a-z0-9]+:[A-Za-z0-9._%:-]*[A-Za-z0-9._%-]")
private val B64U = Regex("[A-Za-z0-9_-]*")
private val P256: ECParameterSpec = AlgorithmParameters.getInstance("EC").run {
    init(ECGenParameterSpec("secp256r1"))
    getParameterSpec(ECParameterSpec::class.java)
}
private val HALF_N: BigInteger = P256.order.shiftRight(1)

/** A P-256 public JWK; [x] and [y] are the 32-byte coordinates in base64url. */
data class Jwk(val kty: String, val crv: String, val x: String, val y: String) {
    internal fun json() = JsonValue.Obj(mapOf("kty" to JsonValue.Str(kty), "crv" to JsonValue.Str(crv), "x" to JsonValue.Str(x), "y" to JsonValue.Str(y)))

    companion object {
        /** The JWK in [json] when it has exactly the string fields kty, crv, x and y, else null. The point is checked where the key is used. */
        fun fromJson(json: JsonValue?): Jwk? {
            if (json !is JsonValue.Obj || json.fields.keys != setOf("kty", "crv", "x", "y")) return null
            return Jwk(json["kty"].str() ?: return null, json["crv"].str() ?: return null, json["x"].str() ?: return null, json["y"].str() ?: return null)
        }
    }
}

/** A key in an owner key log: a device P-256 key (`p256`) or a passkey (`webauthn`). [json] is the credential as the log carries it, label, platform and attestation included. */
data class Credential(val kid: String, val type: String, val jwk: Jwk, val json: JsonValue.Obj) {
    companion object {
        /** Reads a credential stored from a verified key log, with the key log's checks. Throws IllegalArgumentException. */
        fun fromJson(json: JsonValue, rpId: String = RP_ID): Credential = try {
            credential(json, rpId, "credential")
        } catch (e: OpenEntityException) {
            throw IllegalArgumentException(e.message)
        }
    }
}

/** What verifyApproval reads from an owner's verified key log: a [KeyLogState], or these fields stored from one. [root] is read only with `allowRoot`. */
interface OwnerKeys {
    val did: String
    val root: Credential?
    val approvers: List<Credential>
    val closed: Boolean
}

/** The verified state of an owner key log as of `now`. [approvers] may sign approval/2.0 now: the root passkey alone while it is the log's only credential. */
data class KeyLogState(
    override val did: String,
    val seq: Int,
    val head: String,
    override val root: Credential,
    override val approvers: List<Credential>,
    val revoked: List<Revoked>,
    val pending: List<Pending>,
    override val closed: Boolean,
) : OwnerKeys

data class Revoked(val kid: String, val at: Long)
data class Pending(val seq: Int, val op: String, val hash: String, val effectiveAt: Long)
data class ApprovalOk(val kid: String, val counter: Long)

/** Strict base64url: no padding, and only the one encoding of the bytes (re-encoding gives the same string). */
private fun b64u(s: String?): ByteArray? {
    if (s == null || !B64U.matches(s) || s.length % 4 == 1) return null
    val b = try {
        Base64.getUrlDecoder().decode(s)
    } catch (e: IllegalArgumentException) {
        return null
    }
    return if (b64url(b) == s) b else null
}

/** RFC 4648 base32, lowercase, no padding: the owner DID suffix. */
private fun base32(b: ByteArray): String {
    val alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    val out = StringBuilder()
    var bits = 0
    var value = 0
    for (x in b) {
        value = (value shl 8) or (x.toInt() and 0xff)
        bits += 8
        while (bits >= 5) {
            bits -= 5
            out.append(alphabet[(value shr bits) and 31])
        }
        value = value and ((1 shl bits) - 1)
    }
    if (bits > 0) out.append(alphabet[(value shl (5 - bits)) and 31])
    return out.toString()
}

private fun safeInteger(d: Double) = d.isFinite() && d == Math.floor(d) && Math.abs(d) <= MAX_SAFE.toDouble()
private fun uint(v: JsonValue?): Long? = (v as? JsonValue.Num)?.value?.takeIf { safeInteger(it) && it >= 0.0 }?.toLong()

/** Only safe integers and well-formed strings, so every SDK reads an entry or a summary the same way. */
private fun plainJson(v: JsonValue): String? = when (v) {
    is JsonValue.Num -> if (safeInteger(v.value)) null else "number ${v.value} is not an integer within 2^53"
    is JsonValue.Str -> if (hasLoneSurrogate(v.value)) "string has a lone surrogate" else null
    is JsonValue.Arr -> v.items.firstNotNullOfOrNull { plainJson(it) }
    is JsonValue.Obj -> v.fields.entries.firstNotNullOfOrNull { (k, x) -> (if (hasLoneSurrogate(k)) "key has a lone surrogate" else null) ?: plainJson(x) }
    else -> null
}

// ---------------------------------------------------------------- P-256

/** The key, or null unless the JWK is {kty: EC, crv: P-256} with strict base64url 32-byte coordinates of a point on the curve. */
private fun publicKey(jwk: Jwk): PublicKey? {
    if (jwk.kty != "EC" || jwk.crv != "P-256") return null
    val xb = b64u(jwk.x)
    val yb = b64u(jwk.y)
    if (xb == null || yb == null || xb.size != 32 || yb.size != 32) return null
    val x = BigInteger(1, xb)
    val y = BigInteger(1, yb)
    val curve = P256.curve
    val p = (curve.field as ECFieldFp).p
    // ECPublicKeySpec does not check the point: y^2 = x^3 + ax + b (mod p), coordinates below p.
    if (x >= p || y >= p || y.multiply(y).subtract(x.pow(3)).subtract(curve.a.multiply(x)).subtract(curve.b).mod(p).signum() != 0) return null
    return try {
        KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), P256))
    } catch (e: GeneralSecurityException) {
        null
    }
}

/** RFC 7638 JWK thumbprint, base64url: the `kid` of every key in a log. */
private fun thumbprint(j: Jwk) = b64url(sha256("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"${j.x}\",\"y\":\"${j.y}\"}"))

/** Strict DER `SEQUENCE { INTEGER r, INTEGER s }` to 64-byte r||s; null for any other encoding. */
private fun derToRaw(der: ByteArray): ByteArray? {
    fun u(k: Int) = der[k].toInt() and 0xff
    if (der.size < 8 || u(0) != 0x30 || u(1) != der.size - 2 || u(1) > 0x7f) return null
    val out = ByteArray(64)
    var i = 2
    for (at in intArrayOf(0, 32)) {
        if (i + 1 >= der.size || u(i) != 0x02) return null
        val len = u(i + 1)
        if (len < 1 || len > 33 || i + 2 + len > der.size) return null
        val first = u(i + 2)
        if ((first and 0x80) != 0 || (len > 1 && first == 0 && (u(i + 3) and 0x80) == 0) || (len == 33 && first != 0)) return null
        val skip = if (len == 33) 1 else 0
        System.arraycopy(der, i + 2 + skip, out, at + 32 - (len - skip), len - skip)
        i += 2 + len
    }
    return if (i == der.size) out else null
}

/** ECDSA P-256 with SHA-256 over [message] (the JDK hashes it), r and s in [1, n-1], s <= n/2 when [lowS]. A null key never verifies. */
private fun ecdsa(raw: ByteArray, message: ByteArray, pub: PublicKey?, lowS: Boolean): Boolean {
    val r = BigInteger(1, raw.copyOfRange(0, 32))
    val s = BigInteger(1, raw.copyOfRange(32, 64))
    if (pub == null || r.signum() == 0 || r >= P256.order || s.signum() == 0 || s >= P256.order || (lowS && s > HALF_N)) return false
    val a = r.toByteArray() // minimal positive two's complement: the DER INTEGER content
    val b = s.toByteArray()
    val der = byteArrayOf(0x30, (4 + a.size + b.size).toByte(), 0x02, a.size.toByte()) + a + byteArrayOf(0x02, b.size.toByte()) + b
    return try {
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(pub)
            update(message)
            verify(der)
        }
    } catch (e: GeneralSecurityException) {
        false
    }
}

/**
 * A p256 or webauthn signature by [cred] over the digest SHA-256([signed]); returns the WebAuthn signature counter (0 for p256).
 * [signed] is the preimage: the JCS bytes of a key log entry without `auth`, or the UTF-8 approval/2.0 preimage.
 */
private fun checkSignature(cred: Credential, s: JsonValue.Obj, signed: ByteArray, origins: List<String>, rpId: String, lowS: Boolean): Long {
    val form = s["form"].str()
    if (form != cred.type) fail("bad_signature", "a ${cred.type} key cannot present a $form signature")
    val pub = publicKey(cred.jwk) // null only for a hand-built credential; it fails at the ECDSA step, as in the TS SDK
    val sig = b64u(s["signature"].str())!!
    if (form == "p256") {
        if (sig.size != 64 || !ecdsa(sig, signed, pub, lowS)) fail("bad_signature", "p256 signature does not verify")
        return 0
    }
    val authData = b64u(s["authenticator_data"].str())!!
    val clientRaw = b64u(s["client_data_json"].str())!!
    val client = try {
        JsonValue.parse(Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(clientRaw)).toString()) // newDecoder() rejects invalid UTF-8
    } catch (e: CharacterCodingException) {
        fail("bad_webauthn", "clientDataJSON is not UTF-8")
    } catch (e: IllegalArgumentException) {
        fail("bad_webauthn", "clientDataJSON is not JSON")
    }
    if (client["type"].str() != "webauthn.get") fail("bad_webauthn", "clientDataJSON type must be webauthn.get")
    if (client["challenge"].str() != b64url(sha256(signed))) fail("bad_webauthn", "challenge is not the digest")
    if (client["origin"].str().let { it == null || it !in origins }) fail("bad_webauthn", "origin is not accepted")
    if (client["crossOrigin"] == JsonValue.Bool(true)) fail("bad_webauthn", "cross-origin assertions are not accepted")
    if (authData.size < 37 || !authData.copyOf(32).contentEquals(sha256(rpId))) fail("bad_webauthn", "rpIdHash is not SHA-256($rpId)")
    if ((authData[32].toInt() and 0x05) != 0x05) fail("bad_webauthn", "user presence and user verification flags must be set")
    val raw = derToRaw(sig)
    if (raw == null || !ecdsa(raw, authData + sha256(clientRaw), pub, lowS)) fail("bad_signature", "webauthn signature does not verify")
    return ByteBuffer.wrap(authData, 33, 4).int.toLong() and 0xffffffffL
}

/** Shape of the signature fields shared by approvals and key log `auth`. */
private fun signedShape(s: JsonValue.Obj): String? {
    val form = s["form"].str()
    if (form != "p256" && form != "webauthn") return "form must be p256 or webauthn"
    if (b64u(s["signature"].str()) == null) return "signature must be base64url"
    if (form == "webauthn" && (b64u(s["authenticator_data"].str()) == null || b64u(s["client_data_json"].str()) == null)) {
        return "webauthn needs authenticator_data and client_data_json in base64url"
    }
    return null
}

// ---------------------------------------------------------------- approval/2.0

/** Checks every field's form, calling [bad] with the first wrong one, and returns the ADR 0008 preimage. */
private inline fun preimage(verifierDid: String?, ownerDid: String?, requestId: String?, payloadDigest: String?, decision: String?, expiresAt: Long?, bad: (String) -> Nothing): String {
    if (verifierDid == null || !DID.matches(verifierDid)) bad("verifier_did must be a DID")
    if (ownerDid == null || !DID.matches(ownerDid)) bad("owner_did must be a DID")
    if (requestId == null || !REQUEST_ID.matches(requestId)) bad("request_id must be 1 to 128 of [A-Za-z0-9:._-]")
    if (payloadDigest == null || !HEX64.matches(payloadDigest)) bad("payload_digest must be 64 lowercase hex")
    if (decision == null || (decision != "approve" && decision != "deny")) bad("decision must be approve or deny")
    if (expiresAt == null || expiresAt !in 0..MAX_SAFE) bad("expires_at must be unix seconds")
    return listOf("approval/2.0", verifierDid, ownerDid, requestId, payloadDigest, decision, expiresAt.toString()).joinToString("|")
}

/** ADR 0008 preimage: `approval/2.0|verifier_did|owner_did|request_id|payload_digest|decision|expires_at`. A field of the wrong form throws IllegalArgumentException. */
fun approvalPreimage(verifierDid: String, ownerDid: String, requestId: String, payloadDigest: String, decision: String, expiresAt: Long): String =
    preimage(verifierDid, ownerDid, requestId, payloadDigest, decision, expiresAt) { throw IllegalArgumentException(it) }

/** SHA-256 of [approvalPreimage]: what a p256 key signs and what a passkey gets as its challenge (base64url). */
fun approvalDigest(verifierDid: String, ownerDid: String, requestId: String, payloadDigest: String, decision: String, expiresAt: Long): ByteArray =
    sha256(approvalPreimage(verifierDid, ownerDid, requestId, payloadDigest, decision, expiresAt))

/**
 * Lowercase hex SHA-256 of the RFC 8785 form of the summary the owner saw. Numbers must be integers within 2^53 (put amounts
 * in minor units or strings); anything else throws IllegalArgumentException.
 */
fun payloadDigest(summary: JsonValue): String {
    plainJson(summary)?.let { throw IllegalArgumentException(it) }
    return hex(sha256(canonicalize(summary)))
}

/**
 * Verifies an approval/2.0 object against the owner's verified key log ([KeyLogState], or [OwnerKeys] stored from one) and
 * returns the signing key and the WebAuthn counter to store. [requestId] and [payloadDigest] are what this verifier issued and
 * recomputes now, never the client's. [origins] defaults to `https://<rpId>`; add the Android app's `android:apk-key-hash:`
 * origin. [counter] is the counter stored for this key. [allowRoot] also accepts the log's root passkey: off by default, only
 * for account-service flows such as cancelling a deletion request; revoked approvers never sign approvals. Rejects
 * approval/1.0. Throws OpenEntityException with the vector code.
 */
fun verifyApproval(
    approval: JsonValue,
    keyLog: OwnerKeys,
    verifierDid: String,
    ownerDid: String,
    requestId: String,
    payloadDigest: String,
    now: Long,
    decisions: List<String> = listOf("approve", "deny"),
    origins: List<String>? = null,
    rpId: String = RP_ID,
    counter: Long = 0L,
    allowRoot: Boolean = false,
): ApprovalOk {
    if (approval !is JsonValue.Obj) fail("malformed", "approval must be an object")
    if (approval["version"].str() != "approval/2.0") fail("bad_version", "version is not approval/2.0")
    val verifier = approval["verifier_did"].str()
    val owner = approval["owner_did"].str()
    val decision = approval["decision"].str()
    val expiresAt = uint(approval["expires_at"])
    val signed = preimage(verifier, owner, approval["request_id"].str(), approval["payload_digest"].str(), decision, expiresAt) { fail("malformed", it) }
    val device = approval["device_id"].str() ?: fail("malformed", "device_id must be a string")
    signedShape(approval)?.let { fail("malformed", it) }
    if (verifier != verifierDid) fail("wrong_verifier", "approval is for $verifier")
    if (owner != ownerDid || owner != keyLog.did) fail("wrong_owner", "approval names another owner")
    if (keyLog.closed) fail("owner_closed", "the owner's key log is closed")
    if (approval["request_id"].str() != requestId) fail("wrong_request", "the request changed; fetch a new one")
    if (approval["payload_digest"].str() != payloadDigest) fail("wrong_payload", "payload digest does not match the action")
    if (decision !in decisions) fail("bad_decision", "decision $decision is not accepted here")
    val exp = expiresAt!!
    if (now >= exp) fail("expired", "approval expired")
    if (exp > now + MAX_TTL) fail("expiry_too_far", "expires_at is more than 600 seconds away")
    val cred = keyLog.approvers.find { it.kid == device }
        ?: keyLog.root?.takeIf { allowRoot && it.kid == device }
        ?: fail("unknown_key", "device_id is not a current approver in the owner's key log")
    val got = checkSignature(cred, approval, signed.toByteArray(), origins ?: listOf("https://$rpId"), rpId, lowS = false)
    if (approval["form"].str() == "webauthn" && (got != 0L || counter != 0L) && got <= counter) fail("counter_replayed", "signature counter did not increase")
    return ApprovalOk(cred.kid, got)
}

// ---------------------------------------------------------------- key log

private val ENTRY = setOf("v", "seq", "prev", "op", "ts", "body", "auth")
private val BODY = mapOf(
    "genesis" to setOf("approver", "root"),
    "add_approver" to setOf("approver"),
    "recover" to setOf("approvers"),
    "replace_root" to setOf("root"),
    "cancel" to setOf("target"),
    "revoke" to setOf("kid"),
    "close" to emptySet(),
)
private val P256_AUTH = setOf("kid", "form", "signature")
private val WEBAUTHN_AUTH = P256_AUTH + setOf("authenticator_data", "client_data_json")

private fun credential(c: JsonValue?, rpId: String, what: String): Credential {
    if (c !is JsonValue.Obj) fail("malformed", "$what must be a credential object")
    val type = c["type"].str()?.takeIf { it == "p256" || it == "webauthn" } ?: fail("malformed", "$what.type must be p256 or webauthn")
    val jwk = Jwk.fromJson(c["jwk"])
    if (jwk == null || publicKey(jwk) == null) fail("malformed", "$what.jwk must be exactly {kty: EC, crv: P-256, x, y} with a point on the curve")
    val kid = thumbprint(jwk)
    if (c["kid"].str() != kid) fail("malformed", "$what.kid must be the RFC 7638 thumbprint of its jwk")
    if (type == "webauthn" && (b64u(c["credential_id"].str()).let { it == null || it.isEmpty() } || c["rp_id"].str() != rpId)) {
        fail("malformed", "$what needs a credential_id and rp_id $rpId")
    }
    return Credential(kid, type, jwk, c)
}

/** A parsed entry. [creds] are the approvers it adds; [target] is a cancel's target hash or a revoke's kid. */
private class Entry(
    val json: JsonValue.Obj, val seq: Long, val prev: String?, val op: String, val auth: JsonValue.Obj, val kid: String,
    val root: Credential?, val creds: List<Credential>, val target: String,
)

private fun parseEntry(line: String, rpId: String, first: Boolean): Entry {
    val e = try {
        JsonValue.parse(line)
    } catch (x: IllegalArgumentException) {
        fail("malformed", "not JSON: ${x.message}")
    }
    plainJson(e)?.let { fail("malformed", it) }
    if (canonicalize(e) != line) fail("malformed", "line is not the RFC 8785 form of its entry")
    if (e !is JsonValue.Obj || e.fields.keys != ENTRY) fail("malformed", "entry must have exactly v, seq, prev, op, ts, body, auth")
    if (e["v"] != JsonValue.Num(1.0)) fail("malformed", "v must be 1")
    val seq = uint(e["seq"])
    if (seq == null || uint(e["ts"]) == null) fail("malformed", "seq and ts must be unsigned integers")
    val prev = e["prev"]
    if (prev != JsonValue.Null && !HEX64.matches(prev.str() ?: "")) fail("malformed", "prev must be null or 64 lowercase hex")
    val op = e["op"].str()?.takeIf { it in BODY } ?: fail("malformed", "unknown op")
    if ((op == "genesis") != first) fail("malformed", "genesis is the first entry and only the first")
    val body = e["body"]
    val keys = BODY.getValue(op)
    if (body !is JsonValue.Obj || body.fields.keys != keys) fail("malformed", "$op body must have exactly: ${keys.joinToString().ifEmpty { "nothing" }}")
    var root: Credential? = null
    var creds = emptyList<Credential>()
    var target = ""
    when (op) {
        "genesis", "replace_root" -> {
            root = credential(body["root"], rpId, "root")
            if (root.type != "webauthn") fail("malformed", "root must be a passkey (webauthn)")
            if (op == "genesis" && body["approver"] != JsonValue.Null) creds = listOf(credential(body["approver"], rpId, "approver"))
        }
        "add_approver" -> creds = listOf(credential(body["approver"], rpId, "approver"))
        "recover" -> {
            val list = (body["approvers"] as? JsonValue.Arr)?.items
            if (list.isNullOrEmpty()) fail("malformed", "recover needs at least one approver")
            creds = list.mapIndexed { k, c -> credential(c, rpId, "approvers[$k]") }
        }
        "cancel" -> target = body["target"].str()?.takeIf { HEX64.matches(it) } ?: fail("malformed", "target must be 64 lowercase hex")
        "revoke" -> target = body["kid"].str() ?: fail("malformed", "kid must be a string")
    }
    val auth = e["auth"]
    val kid = auth["kid"].str()
    if (auth !is JsonValue.Obj || kid == null) fail("malformed", "auth must be an object with a kid")
    val authKeys = if (auth["form"].str() == "webauthn") WEBAUTHN_AUTH else P256_AUTH
    (signedShape(auth) ?: if (auth.fields.keys == authKeys) null else "auth must have exactly ${authKeys.joinToString()}")?.let { fail("malformed", it) }
    return Entry(e, seq, prev.str(), op, auth, kid, root, creds, target)
}

private class PendingOp(val seq: Int, val op: String, val hash: String, val effectiveAt: Long, val creds: List<Credential>)

/**
 * Verifies an owner key log (JSON Lines, one RFC 8785 entry per line) against the owner DID it must hash to and returns its
 * state as of [now] (unix seconds). [firstSeenAt] holds, per entry, when this verifier first held it with its whole chain
 * (unix seconds, never decreasing): every delay runs from it, never from the entry's `ts`. [serviceKeys] are the account
 * service's P-256 close keys, current and retired (any of them may sign `close`); an invalid one throws IllegalArgumentException. [origins] defaults to
 * `https://<rpId>`; add the Android app's `android:apk-key-hash:` origin. The first failing entry throws OpenEntityException
 * with its code and seq.
 */
fun verifyKeyLog(
    did: String,
    lines: List<String>,
    firstSeenAt: List<Long>,
    now: Long,
    serviceKeys: List<Jwk> = emptyList(),
    origins: List<String>? = null,
    rpId: String = RP_ID,
): KeyLogState {
    val accepted = origins ?: listOf("https://$rpId")
    val services = serviceKeys.map { jwk ->
        require(publicKey(jwk) != null) { "serviceKeys must be P-256 public JWKs {kty, crv, x, y}" }
        val kid = thumbprint(jwk)
        Credential(kid, "p256", jwk, JsonValue.Obj(mapOf("kid" to JsonValue.Str(kid), "type" to JsonValue.Str("p256"), "jwk" to jwk.json())))
    }
    var seq = 1
    try {
        if (lines.isEmpty()) fail("malformed", "a key log starts with its genesis entry")
        if (firstSeenAt.size != lines.size) fail("bad_first_seen", "one first_seen_at per entry")
        lateinit var root: Credential
        var single = false
        var closed = false
        var head = ""
        var approvers = listOf<Credential>()
        var pending = listOf<PendingOp>()
        val revoked = mutableListOf<Pair<Credential, Long>>()
        val seen = HashSet<String>()
        val delayed = HashMap<String, String>() // entry hash of every recover and replace_root -> its op

        fun approver(kid: String) = (if (single) listOf(root) else approvers).find { it.kid == kid }
        fun due(t: Long) {
            while (pending.isNotEmpty() && pending[0].effectiveAt <= t) {
                val p = pending[0]
                pending = pending.drop(1)
                if (p.op == "replace_root") {
                    root = p.creds[0]
                } else {
                    approvers.forEach { revoked += it to p.effectiveAt }
                    approvers = p.creds
                    single = false
                }
            }
        }
        fun fresh(creds: List<Credential>) {
            for (c in creds) if (!seen.add(c.kid)) fail("key_reused", "key ${c.kid} is already in this log")
        }

        for ((i, line) in lines.withIndex()) {
            seq = i + 1
            val t = firstSeenAt[i]
            if (t !in 0..MAX_SAFE || t > now || (i > 0 && t < firstSeenAt[i - 1])) {
                fail("bad_first_seen", "first_seen_at must be unix seconds, never decreasing, not after now")
            }
            if (i > 0) due(t)
            val e = parseEntry(line, rpId, i == 0)
            if (closed) fail("closed", "the log is closed")
            if (e.seq != seq.toLong()) fail("bad_seq", "seq must be $seq")
            if (e.prev != (if (i > 0) head else null)) fail("bad_prev", if (i > 0) "prev is not the SHA-256 of the previous entry" else "genesis prev must be null")
            val hash = hex(sha256(line))
            val signer = when (e.op) {
                "genesis" -> {
                    if (did != "did:web:$rpId:o:${base32(sha256(line))}") fail("did_mismatch", "the genesis hash does not match the DID suffix")
                    root = e.root!!
                    val firstApprover = e.creds.firstOrNull()
                    fresh(listOfNotNull(root, firstApprover))
                    single = firstApprover == null
                    approvers = listOfNotNull(firstApprover)
                    (firstApprover ?: root).takeIf { it.kid == e.kid }
                }
                "add_approver" -> {
                    fresh(e.creds)
                    approver(e.kid)
                }
                "recover" -> {
                    fresh(e.creds)
                    root.takeIf { it.kid == e.kid }
                }
                "replace_root" -> {
                    fresh(listOf(e.root!!))
                    if (root.kid == e.kid) root else approver(e.kid)
                }
                "cancel" -> {
                    val op = delayed[e.target] ?: fail("bad_target", "target is not a recover or replace_root in this log")
                    approver(e.kid)
                        ?: revoked.find { (c, at) -> c.kid == e.kid && t < at + WEEK }?.first
                        ?: root.takeIf { op == "recover" && it.kid == e.kid }
                }
                "revoke" -> {
                    if (approvers.none { it.kid == e.target }) fail("bad_target", "kid is not a current approver")
                    if (root.kid == e.kid) root else approver(e.kid)
                }
                else -> services.find { it.kid == e.kid } // close
            } ?: fail("unauthorized", "key ${e.kid} may not sign ${e.op} here")
            checkSignature(signer, e.auth, canonicalize(JsonValue.Obj(e.json.fields - "auth")).toByteArray(), accepted, rpId, lowS = true)

            when (e.op) {
                "add_approver" -> {
                    approvers = approvers + e.creds
                    single = false
                }
                "recover" -> {
                    pending = pending + PendingOp(seq, "recover", hash, t + DAY, e.creds)
                    delayed[hash] = "recover"
                }
                "replace_root" -> {
                    if (single) root = e.root!! else pending = pending + PendingOp(seq, "replace_root", hash, t + DAY, listOf(e.root!!))
                    delayed[hash] = "replace_root"
                }
                "cancel" -> pending = pending.filter { it.hash != e.target }
                "revoke" -> {
                    val gone = approvers.first { it.kid == e.target }
                    approvers = approvers.filter { it.kid != e.target }
                    revoked += gone to t
                }
                "close" -> {
                    closed = true
                    pending = emptyList()
                }
            }
            head = hash
        }
        due(now)
        return KeyLogState(
            did, lines.size, head, root, if (single) listOf(root) else approvers,
            revoked.map { Revoked(it.first.kid, it.second) }, pending.map { Pending(it.seq, it.op, it.hash, it.effectiveAt) }, closed,
        )
    } catch (x: OpenEntityException) {
        throw OpenEntityException(x.code, seq, x.message.orEmpty())
    }
}
