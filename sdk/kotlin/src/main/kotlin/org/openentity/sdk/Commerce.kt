// OEIS Commerce Profile (spec/commerce-profile.md): mandate/1, cart/1, receipt/1 and the one-call checkout check, ported from
// sdk/ts/src/commerce.ts with the same checks in the same order and the same error codes. Owners sign mandates on their devices,
// products verify; the only thing this file signs is a receipt, by the merchant or the agent. CommerceTest runs
// test-vectors/{mandate-1,cart-1,receipt-1,checkout-1}, the same files the TS and Python SDKs run.
package org.openentity.sdk

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.time.Instant
import java.time.temporal.ChronoUnit

private const val MAX_TTL = 90 * DAY
private val MD_ID = Regex("md_[a-z2-7]{26}")
private val RC_ID = Regex("rc_[a-z2-7]{26}")
private val CCY = Regex("[A-Z]{3}")
private val APPROVAL_REQUEST_ID = Regex("[A-Za-z0-9:._-]{1,128}")
private val HTTPS_URL = Regex("https://[^\\s\\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff]+") // JS \\s, so TS and Kotlin agree
private val HOST = Regex("[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:\\d+)?")
private val PERIODS = listOf("P1D", "P7D", "P1M")
private val BANDS = listOf("poor", "fair", "good", "strong")

/** The payment rails a mandate or a cart can name. */
val RAILS = listOf("card", "x402", "mpp", "credits", "usdc")

private fun JsonValue?.obj() = this as? JsonValue.Obj
private fun JsonValue?.arr() = (this as? JsonValue.Arr)?.items
private fun JsonValue.Obj.hasOnly(vararg keys: String) = fields.keys == keys.toSet()
private fun strs(v: JsonValue?) = v.arr()?.all { it.str().let { s -> s != null && s.isNotEmpty() && s.length <= 253 } } == true
private fun strList(v: JsonValue?) = v.arr()!!.map { it.str()!! }
private fun JsonValue.Obj.uint(key: String) = uint(fields[key])

// ---------------------------------------------------------------- cart/1

private val CART_KEYS = listOf("profile", "merchant", "agent_did", "lines", "total", "currency", "rail", "mandate_id")
private val LINE_KEYS = setOf("sku", "title", "qty", "unit")

/** null when [c] is a well-formed cart/1 summary, else why not. */
fun cartError(c: JsonValue): String? {
    if (c !is JsonValue.Obj || c.fields.keys != CART_KEYS.toSet()) return "cart/1 has exactly: ${CART_KEYS.joinToString(", ")}"
    if (c["profile"].str() != "cart/1") return "profile must be cart/1"
    if (c["merchant"].str()?.let { DID.matches(it) } != true) return "merchant must be a DID"
    if (c["agent_did"].str()?.let { DID.matches(it) } != true) return "agent_did must be a DID"
    if (c["currency"].str()?.let { CCY.matches(it) } != true) return "currency must be 3 uppercase letters"
    if (c["rail"].str() !in RAILS) return "rail must be one of ${RAILS.joinToString(", ")}"
    val mid = c["mandate_id"]
    if (mid != JsonValue.Null && mid.str()?.let { MD_ID.matches(it) } != true) return "mandate_id must be md_<26 base32> or null"
    val lines = c["lines"].arr()
    if (lines == null || lines.isEmpty() || lines.size > 100) return "lines must hold 1 to 100 lines"
    var sum = 0L
    for (l in lines) {
        if (l !is JsonValue.Obj) return "a line must be an object"
        val keys = if ("category" in l.fields) LINE_KEYS + "category" else LINE_KEYS
        if (l.fields.keys != keys) return "a line has exactly: ${keys.joinToString(", ")}"
        if (l["sku"].str().isNullOrEmpty() || l["title"].str() == null || ("category" in l.fields && l["category"].str() == null)) return "sku, title and category must be strings"
        val qty = l.uint("qty")
        val unit = l.uint("unit")
        if (qty == null || qty == 0L || unit == null) return "qty must be a positive integer and unit an integer in minor units"
        // a product beyond 2^53 can never equal a safe-integer total
        sum = try { Math.addExact(sum, Math.multiplyExact(qty, unit)) } catch (e: ArithmeticException) { Long.MAX_VALUE }
    }
    val total = c.uint("total")
    if (total == null || total != sum) return "total must equal the sum of qty * unit"
    return plainJson(c)
}

/** Lowercase hex payload digest of a cart/1 summary: the `payload_digest` of the approval/2.0 that approves this purchase. Throws IllegalArgumentException for a malformed cart. */
fun cartDigest(cart: JsonValue): String {
    cartError(cart)?.let { throw IllegalArgumentException(it) }
    return payloadDigest(cart)
}

// ---------------------------------------------------------------- mandate/1

data class Limits(val currency: String, val perTxMax: Long, val period: String, val periodMax: Long, val totalMax: Long)
data class Scope(val merchants: List<String>, val categories: List<String>?, val rails: List<String>)

/** What a verified mandate allows: the fields [mandateCovers] reads. */
data class MandateTerms(val mandateId: String, val agentDid: String, val limits: Limits, val scope: Scope, val stepUpOver: Long) {
    companion object {
        /** Reads a mandate/1 object (signature not checked: verifyMandate does that). Throws IllegalArgumentException when a field is malformed. */
        fun fromJson(mandate: JsonValue): MandateTerms {
            val m = mandate as? JsonValue.Obj ?: throw IllegalArgumentException("mandate must be an object")
            mandateFieldsError(m)?.let { throw IllegalArgumentException(it) }
            val l = m["limits"].obj()!!
            val s = m["scope"].obj()!!
            return MandateTerms(
                m["mandate_id"].str()!!, m["agent_did"].str()!!,
                Limits(l["currency"].str()!!, l.uint("per_tx_max")!!, l["period"].str()!!, l.uint("period_max")!!, l.uint("total_max")!!),
                Scope(strList(s["merchants"]), s["categories"]?.let { strList(it) }, strList(s["rails"])), m.uint("step_up_over")!!,
            )
        }
    }
}

private val MANDATE_KEYS = listOf("version", "mandate_id", "issuer_did", "agent_did", "issued_at", "expires_at", "limits", "scope", "step_up_over", "status", "signature")

internal fun mandateFieldsError(m: JsonValue.Obj): String? {
    val f = m.fields
    if (f.keys.any { it !in MANDATE_KEYS && it != "ap2" } || MANDATE_KEYS.any { it !in f }) return "mandate/1 has ${MANDATE_KEYS.joinToString(", ")} and optionally ap2"
    if (m["mandate_id"].str()?.let { MD_ID.matches(it) } != true) return "mandate_id must be md_<26 base32>"
    if (m["issuer_did"].str()?.let { DID.matches(it) } != true) return "issuer_did must be a DID"
    if (m["agent_did"].str()?.let { DID.matches(it) } != true) return "agent_did must be a DID"
    val issued = m.uint("issued_at")
    val expires = m.uint("expires_at")
    if (issued == null || expires == null || expires <= issued) return "issued_at and expires_at must be unix seconds, expires after issued"
    if (expires - issued > MAX_TTL) return "a mandate lasts at most 90 days"
    val l = m["limits"].obj()
    if (l == null || !l.hasOnly("currency", "per_tx_max", "period", "period_max", "total_max")) return "limits must be {currency, per_tx_max, period, period_max, total_max}"
    if (l["currency"].str()?.let { CCY.matches(it) } != true || l["period"].str() !in PERIODS) return "limits.currency must be 3 uppercase letters and period one of ${PERIODS.joinToString(", ")}"
    if (l.uint("per_tx_max") == null || l.uint("period_max") == null || l.uint("total_max") == null) return "limits amounts must be integers in minor units"
    val s = m["scope"].obj()
    if (s == null || s.fields.keys.any { it !in listOf("merchants", "categories", "rails") } || "merchants" !in s.fields || "rails" !in s.fields) return "scope must be {merchants, categories?, rails}"
    if (!strs(s["merchants"]) || ("categories" in s.fields && !strs(s["categories"]))) return "scope.merchants and scope.categories must be arrays of strings"
    val rails = s["rails"].arr()
    if (rails == null || rails.isEmpty() || rails.any { it.str() !in RAILS }) return "scope.rails must be a non-empty subset of ${RAILS.joinToString(", ")}"
    if (m.uint("step_up_over") == null) return "step_up_over must be an integer in minor units"
    if (m["status"].str()?.let { HTTPS_URL.matches(it) } != true) return "status must be an https URL"
    if ("ap2" in f) {
        val a = m["ap2"].obj()
        if (a == null || !a.hasOnly("checkout_mandate_hash") || a["checkout_mandate_hash"].let { it != JsonValue.Null && it.str() == null }) return "ap2 must be {checkout_mandate_hash: string | null}"
    }
    val sig = m["signature"].obj()
    if (sig == null || sig["device_id"].str() == null) return "signature must hold device_id, form, signature"
    val keys = if (sig["form"].str() == "webauthn") setOf("device_id", "form", "signature", "authenticator_data", "client_data_json") else setOf("device_id", "form", "signature")
    return signedShape(sig) ?: if (sig.fields.keys == keys) plainJson(m) else "signature must have exactly ${keys.joinToString(", ")}"
}

private fun mandatePreimage(m: JsonValue.Obj) = "mandate/1|*|" + canonicalize(JsonValue.Obj(m.fields - "signature"))

/** SHA-256 of `mandate/1|*|` + the RFC 8785 form of the mandate without its signature. The `*` is the verifier scope: any merchant may rely on it. Throws IllegalArgumentException for a non-object. */
fun mandateDigest(mandate: JsonValue): ByteArray =
    sha256(mandatePreimage(mandate as? JsonValue.Obj ?: throw IllegalArgumentException("mandate must be an object")))

sealed class MandateResult {
    data class Ok(val kid: String, val terms: MandateTerms, val periodSpent: Long?, val totalSpent: Long?) : MandateResult()
    /** [error]: malformed, bad_version, wrong_owner, owner_closed, wrong_agent, not_yet_valid, expired, unknown_key, bad_signature, bad_webauthn, revoked, exhausted or status_required. */
    data class Err(val error: String, val message: String) : MandateResult()
}

/**
 * Verifies a mandate/1 against the issuer's key log ([keyLog]: a [KeyLogState] or [OwnerKeys] stored from one). Revocation is
 * [status]: the answer of the mandate's status URL, fetched by the caller (max-age 60 or less); without it a mandate is accepted
 * only if it expires within a day. [agentDid] is the agent presenting the mandate, from a verified request signature; null only to
 * inspect a mandate. Spend accounting stays with the enforcing product.
 */
fun verifyMandate(
    mandate: JsonValue,
    keyLog: OwnerKeys,
    agentDid: String?,
    now: Long,
    status: JsonValue? = null,
    origins: List<String>? = null,
    rpId: String = RP_ID,
): MandateResult = try {
    val m = mandate as? JsonValue.Obj ?: fail("malformed", "mandate must be an object")
    if (m["version"].str() != "mandate/1") fail("bad_version", "version is not mandate/1")
    mandateFieldsError(m)?.let { fail("malformed", it) }
    val terms = MandateTerms.fromJson(m)
    val sig = m["signature"].obj()!!
    if (m["issuer_did"].str() != keyLog.did) fail("wrong_owner", "the mandate names another owner")
    if (keyLog.closed) fail("owner_closed", "the owner's key log is closed")
    if (agentDid != null && terms.agentDid != agentDid) fail("wrong_agent", "the mandate is for another agent")
    if (now < m.uint("issued_at")!!) fail("not_yet_valid", "the mandate is issued in the future")
    val expires = m.uint("expires_at")!!
    if (now >= expires) fail("expired", "the mandate expired")
    val cred = keyLog.approvers.find { it.kid == sig["device_id"].str() } ?: fail("unknown_key", "device_id is not a current approver in the owner's key log")
    checkSignature(cred, sig, mandatePreimage(m).toByteArray(), origins ?: listOf("https://$rpId"), rpId, lowS = false)
    var periodSpent: Long? = null
    var totalSpent: Long? = null
    if (status != null) {
        // A status answer that is not exactly what section 2.2 says is no answer: it never lets a mandate through.
        val st = status.obj()
        periodSpent = st?.uint("period_spent")
        totalSpent = st?.uint("total_spent")
        if (st == null || st["status"].str() !in listOf("active", "revoked", "exhausted")
            || ("mandate_id" in st.fields && st["mandate_id"].str() != terms.mandateId)
            || ("period_spent" in st.fields && periodSpent == null) || ("total_spent" in st.fields && totalSpent == null)
        ) fail("status_required", "the status answer is malformed or for another mandate")
        if (st["status"].str() == "revoked") fail("revoked", "the owner revoked the mandate")
        if (st["status"].str() == "exhausted") fail("exhausted", "the mandate is spent")
    } else if (expires - now > DAY) fail("status_required", "a mandate with more than a day left needs a fresh status answer")
    MandateResult.Ok(cred.kid, terms, periodSpent, totalSpent)
} catch (e: OpenEntityException) {
    MandateResult.Err(e.code, e.message.orEmpty())
}

/** The host of a did:web DID, lowercase, without port; null for other methods and for anything that is not a plain hostname (%2F, %23, %3F, a bad escape). */
private fun didHost(did: String): String? {
    if (!did.startsWith("did:web:")) return null
    val d = percentDecode(did.substring(8).substringBefore(':'))?.lowercase() ?: return null
    return if (HOST.matches(d)) d.substringBefore(':') else null
}

/** decodeURIComponent: %XX bytes read as strict UTF-8; null for a bad escape or invalid UTF-8. */
private fun percentDecode(s: String): String? {
    val out = java.io.ByteArrayOutputStream()
    var i = 0
    while (i < s.length) {
        if (s[i] == '%') {
            val hi = if (i + 2 < s.length) hexValue(s[i + 1]) else -1
            val lo = if (i + 2 < s.length) hexValue(s[i + 2]) else -1
            if (hi < 0 || lo < 0) return null
            out.write(hi * 16 + lo)
            i += 3
        } else {
            val cp = s.codePointAt(i)
            out.write(String(Character.toChars(cp)).toByteArray())
            i += Character.charCount(cp)
        }
    }
    return try {
        Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(out.toByteArray())).toString()
    } catch (e: CharacterCodingException) {
        null
    }
}

private fun merchantAllowed(patterns: List<String>, merchant: String): Boolean {
    if (patterns.isEmpty()) return true
    val host = didHost(merchant)
    return patterns.any { p ->
        if (p == merchant) return@any true
        if (p.startsWith("did:") || host == null) return@any false
        val d = p.lowercase()
        if (d.startsWith("*.")) host.endsWith(d.substring(1)) else host == d
    }
}

/** [reason]: bad_cart, wrong_agent, wrong_mandate, wrong_currency, out_of_scope or over_limit. [stepUpRequired]: the cart fits but is above `step_up_over`, so the owner must approve this exact cart (approval/2.0 over [cartDigest]). */
data class Coverage(val ok: Boolean, val stepUpRequired: Boolean = false, val reason: String? = null, val detail: String? = null)

/** Whether a verified mandate allows this cart. [periodSpent] and [totalSpent] are the enforcing product's counters (a negative one never fits). */
fun mandateCovers(mandate: MandateTerms, cart: JsonValue, periodSpent: Long? = null, totalSpent: Long? = null): Coverage {
    fun no(reason: String, detail: String) = Coverage(false, false, reason, detail)
    cartError(cart)?.let { return no("bad_cart", it) }
    val c = cart as JsonValue.Obj
    val l = mandate.limits
    val s = mandate.scope
    val total = c.uint("total")!!
    if (c["agent_did"].str() != mandate.agentDid) return no("wrong_agent", "the cart is for another agent")
    val cartMandate = c["mandate_id"].str()
    if (cartMandate != null && cartMandate != mandate.mandateId) return no("wrong_mandate", "the cart names another mandate")
    if (c["currency"].str() != l.currency) return no("wrong_currency", "the mandate is in ${l.currency}")
    if (c["rail"].str() !in s.rails) return no("out_of_scope", "rail ${c["rail"].str()} is not in scope")
    if (!merchantAllowed(s.merchants, c["merchant"].str()!!)) return no("out_of_scope", "merchant ${c["merchant"].str()} is not in scope")
    if (!s.categories.isNullOrEmpty() && c["lines"].arr()!!.any { it["category"].str().let { cat -> cat == null || cat.isEmpty() || cat !in s.categories } }) return no("out_of_scope", "a line is outside the categories")
    if (listOf(periodSpent, totalSpent).any { it != null && it !in 0..9_007_199_254_740_991L }) return no("over_limit", "spent must be unsigned safe integers")
    if (total > l.perTxMax) return no("over_limit", "per_tx_max")
    if ((periodSpent ?: 0) + total > l.periodMax) return no("over_limit", "period_max")
    if ((totalSpent ?: 0) + total > l.totalMax) return no("over_limit", "total_max")
    return Coverage(true, total > mandate.stepUpOver)
}

// ---------------------------------------------------------------- receipt/1

enum class Party(val wire: String) { MERCHANT("merchant"), AGENT("agent") }

private val RECEIPT_KEYS = setOf(
    "version", "receipt_id", "kind", "refers_to", "merchant_did", "agent_did", "mandate_id", "mandate_hash", "cart_digest",
    "approval_request_id", "total", "currency", "rail", "settlement_ref", "created_at",
)

/** null when [r] is a well-formed receipt/1 (proofs aside), else why not. */
fun receiptError(r: JsonValue): String? {
    if (r !is JsonValue.Obj) return "receipt must be an object"
    val f = r.fields
    if (f.keys.any { it !in RECEIPT_KEYS && it != "proofs" } || RECEIPT_KEYS.any { it !in f }) return "receipt/1 has exactly: ${RECEIPT_KEYS.joinToString(", ")}, proofs"
    if (r["version"].str() != "receipt/1") return "version must be receipt/1"
    if (r["receipt_id"].str()?.let { RC_ID.matches(it) } != true) return "receipt_id must be rc_<26 base32>"
    val kind = r["kind"].str()
    if (kind !in listOf("purchase", "refund", "chargeback")) return "kind must be purchase, refund or chargeback"
    val refersTo = r["refers_to"]
    if (if (kind == "purchase") refersTo != JsonValue.Null else refersTo.str()?.let { RC_ID.matches(it) } != true) return "refers_to is null for a purchase and the purchase's receipt_id for a refund or chargeback"
    val merchant = r["merchant_did"].str()
    val agent = r["agent_did"].str()
    if (merchant == null || !DID.matches(merchant) || agent == null || !DID.matches(agent)) return "merchant_did and agent_did must be DIDs"
    if (merchant == agent) return "merchant_did and agent_did must differ"
    val mid = r["mandate_id"]
    val mhash = r["mandate_hash"]
    if (mid != JsonValue.Null && mid.str()?.let { MD_ID.matches(it) } != true) return "mandate_id must be md_<26 base32> or null"
    if (mhash != JsonValue.Null && mhash.str()?.let { HEX64.matches(it) } != true) return "mandate_hash must be 64 lowercase hex or null"
    if ((mid == JsonValue.Null) != (mhash == JsonValue.Null)) return "mandate_id and mandate_hash go together"
    if (r["cart_digest"].str()?.let { HEX64.matches(it) } != true) return "cart_digest must be 64 lowercase hex"
    val ar = r["approval_request_id"]
    if (ar != JsonValue.Null && ar.str()?.let { APPROVAL_REQUEST_ID.matches(it) } != true) return "approval_request_id must be a request id or null"
    if (r.uint("total") == null || r.uint("created_at") == null) return "total and created_at must be unsigned integers"
    if (r["currency"].str()?.let { CCY.matches(it) } != true) return "currency must be 3 uppercase letters"
    if (r["rail"].str() !in RAILS) return "rail must be one of ${RAILS.joinToString(", ")}"
    if (r["settlement_ref"].str().let { it == null || it.isEmpty() || it.length > 256 }) return "settlement_ref must be 1 to 256 characters"
    if ("proofs" in f && r["proofs"] !is JsonValue.Arr) return "proofs must be an array"
    return plainJson(r)
}

/**
 * Adds [by]'s eddsa-jcs-2022 proof, made with the 32-byte Ed25519 [seed]. Both parties sign the same bytes (the receipt without
 * `proofs`), so the buyer countersigns without seeing the merchant's proof. The signer is the receipt's `merchant_did` or
 * `agent_did`; a did:key signer needs no [verificationMethod], a did:web merchant passes its own. A seed that is not the DID's key
 * fails here, never later. Throws IllegalArgumentException for a malformed receipt, a repeat signature or a wrong seed.
 */
fun signReceipt(receipt: JsonValue, seed: ByteArray, by: Party, created: String = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString(), verificationMethod: String? = null): JsonValue.Obj {
    receiptError(receipt)?.let { throw IllegalArgumentException(it) }
    val r = receipt as JsonValue.Obj
    val did = r[if (by == Party.MERCHANT) "merchant_did" else "agent_did"].str()!!
    val method = verificationMethod ?: if (did.startsWith("did:key:")) "$did#${did.removePrefix("did:key:")}" else throw IllegalArgumentException("a $did signer passes its verificationMethod")
    require(method.substringBefore('#') == did) { "${by.wire}_did is not the signing key's DID" }
    val proofs = r["proofs"].arr().orEmpty()
    require(proofs.none { it["by"].str() == by.wire }) { "already signed by ${by.wire}" }
    val config = linkedMapOf<String, JsonValue>(
        "type" to JsonValue.Str("DataIntegrityProof"), "cryptosuite" to JsonValue.Str("eddsa-jcs-2022"), "created" to JsonValue.Str(created),
        "verificationMethod" to JsonValue.Str(method), "proofPurpose" to JsonValue.Str("assertionMethod"),
    )
    val sig = ed25519Sign(seed, sha256(canonicalize(JsonValue.Obj(config))) + sha256(canonicalize(JsonValue.Obj(r.fields - "proofs"))))
    val proof = JsonValue.Obj(linkedMapOf<String, JsonValue>("by" to JsonValue.Str(by.wire)) + config + ("proofValue" to JsonValue.Str("z" + base58Encode(sig))))
    if (did.startsWith("did:key:")) {
        try {
            verifyProof(r, JsonValue.Obj(proof.fields - "by"))
        } catch (e: OpenEntityException) {
            throw IllegalArgumentException("the seed is not the key of $did")
        }
    }
    return JsonValue.Obj(r.fields + ("proofs" to JsonValue.Arr(proofs + proof)))
}

sealed class ReceiptResult {
    data class Ok(val signedBy: List<Party>) : ReceiptResult()
    /** [error]: malformed, missing_proof, wrong_signer or bad_proof. */
    data class Err(val error: String, val message: String) : ReceiptResult()
}

/**
 * Verifies the proofs on a receipt. [require] (default the merchant only) lists who must have signed; any proof present must
 * verify, and its signer must be the receipt's `merchant_did` or `agent_did` named by `by`. Pass a [DidWebResolver] for did:web parties.
 */
fun verifyReceipt(receipt: JsonValue, resolver: Resolver = Resolver.DID_KEY, require: List<Party> = listOf(Party.MERCHANT)): ReceiptResult {
    receiptError(receipt)?.let { return ReceiptResult.Err("malformed", it) }
    val r = receipt as JsonValue.Obj
    val signed = mutableListOf<Party>()
    for (p in r["proofs"].arr().orEmpty()) {
        val by = Party.entries.find { p["by"].str() == it.wire }
        if (p !is JsonValue.Obj || by == null || by in signed) return ReceiptResult.Err("malformed", "each proof names a distinct by: merchant or agent")
        val proof = JsonValue.Obj(p.fields - "by")
        if (proof["verificationMethod"].str()?.substringBefore('#') != r["${by.wire}_did"].str()) return ReceiptResult.Err("wrong_signer", "the ${by.wire} proof is not by ${by.wire}_did")
        try {
            verifyProof(r, proof, resolver)
        } catch (e: OpenEntityException) {
            return ReceiptResult.Err("bad_proof", "${by.wire}: ${e.code}")
        }
        signed += by
    }
    for (need in require) if (need !in signed) return ReceiptResult.Err("missing_proof", "no ${need.wire} proof")
    return ReceiptResult.Ok(signed)
}

sealed class ChainResult {
    data class Ok(val refunded: Long) : ChainResult()
    /** [error]: malformed, not_purchase, mismatch or over_refund. */
    data class Err(val error: String, val message: String) : ChainResult()
}

/** Structural check that refunds and chargebacks are consistent with their purchase: each refers_to the purchase, same parties, currency and rail, no repeated receipt_id, and their sum at most the purchase total. Proofs are [verifyReceipt]'s job; run both. */
fun verifyReceiptChain(purchase: JsonValue, later: List<JsonValue>): ChainResult {
    (listOf(purchase) + later).firstNotNullOfOrNull { receiptError(it) }?.let { return ChainResult.Err("malformed", it) }
    val p = purchase as JsonValue.Obj
    if (p["kind"].str() != "purchase") return ChainResult.Err("not_purchase", "the first receipt must be a purchase")
    val ids = hashSetOf(p["receipt_id"].str())
    var refunded = 0L
    for (x in later.map { it as JsonValue.Obj }) {
        if (x["kind"].str() == "purchase" || x["refers_to"].str() != p["receipt_id"].str()) return ChainResult.Err("mismatch", "each later receipt must be a refund or chargeback of this purchase")
        if (!ids.add(x["receipt_id"].str())) return ChainResult.Err("mismatch", "receipt_id repeats")
        if (listOf("merchant_did", "agent_did", "currency", "rail").any { x[it].str() != p[it].str() }) return ChainResult.Err("mismatch", "parties, currency and rail must equal the purchase's")
        refunded += x.uint("total")!!
    }
    if (refunded > p.uint("total")!!) return ChainResult.Err("over_refund", "refunds and chargebacks exceed the purchase total")
    return ChainResult.Ok(refunded)
}

// ---------------------------------------------------------------- the checkout check

/** The merchant's rules for an agent at checkout. */
data class AgentPolicy(
    val minLevel: Int? = null,
    val requireOwner: Boolean = false,
    val requireMandate: Boolean = false,
    val minSecurityBand: String? = null,
    val acceptIssuers: List<String> = emptyList(),
)

/** What the caller knows about the agent from the registry: never taken from the request. */
data class AgentFacts(val level: Int? = null, val ownerDid: String? = null, val securityBand: String? = null, val securityIssuer: String? = null)

/** The owner's per-cart approval/2.0 for this exact cart: [verifierDid] and [requestId] are the merchant's own; [counter] is the WebAuthn counter stored for the signing key (store evidence `approval_counter` after an allow). */
data class CheckoutApproval(val approval: JsonValue, val verifierDid: String, val requestId: String, val counter: Long = 0L)

/** [decision] is allow, step_up or deny; [evidence] holds strings and longs (agent_did, mandate_id, mandate_hash, approval_request_id, approval_kid, approval_counter, approval_error). */
data class CheckoutDecision(val decision: String, val reasons: List<String>, val evidence: Map<String, Any>)

/**
 * The one-call check behind Agent Commerce Check: agent, owner, mandate, cart and merchant policy in, `allow`, `step_up` or `deny`
 * with reasons out. Deny is final (wrong agent, dead mandate, policy unmet); step_up means an owner approval of this exact cart
 * would allow. [agentDid] must come from a verified request signature (RFC 9421, which this SDK does not carry): never from a
 * header or a body field. [mandate] needs [keyLog], the mandate issuer's verified key log; [status] is the mandate status answer.
 */
fun verifyAgentForCheckout(
    agentDid: String?,
    cart: JsonValue,
    merchantPolicy: AgentPolicy,
    now: Long,
    agent: AgentFacts = AgentFacts(),
    mandate: JsonValue? = null,
    keyLog: OwnerKeys? = null,
    status: JsonValue? = null,
    approval: CheckoutApproval? = null,
    origins: List<String>? = null,
): CheckoutDecision {
    val evidence = linkedMapOf<String, Any>()
    fun deny(vararg reasons: String) = CheckoutDecision("deny", reasons.toList(), evidence)
    if (cartError(cart) != null) return deny("bad_cart")
    val c = cart as JsonValue.Obj
    if (agentDid == null) return deny("request_unverified")
    evidence["agent_did"] = agentDid
    if (c["agent_did"].str() != agentDid) return deny("agent_mismatch")

    val reasons = mutableListOf<String>()
    if (merchantPolicy.minLevel != null && (agent.level ?: -1) < merchantPolicy.minLevel) reasons += "level_too_low"
    if (merchantPolicy.minSecurityBand != null) {
        val need = BANDS.indexOf(merchantPolicy.minSecurityBand)
        val got = BANDS.indexOf(agent.securityBand ?: "")
        if (got < 0 || got < need) reasons += "security_band_too_low"
        else if (merchantPolicy.acceptIssuers.isNotEmpty() && (agent.securityIssuer ?: "") !in merchantPolicy.acceptIssuers) reasons += "issuer_not_accepted"
    }

    var owner = agent.ownerDid
    var covered: Coverage? = null
    if (mandate != null) {
        if (keyLog == null) return deny("no_key_log")
        val v = verifyMandate(mandate, keyLog, agentDid, now, status, origins)
        if (v is MandateResult.Err) return deny("mandate_${v.error}")
        v as MandateResult.Ok
        owner = (mandate as JsonValue.Obj)["issuer_did"].str()
        evidence["mandate_id"] = v.terms.mandateId
        evidence["mandate_hash"] = hex(mandateDigest(mandate))
        val cv = mandateCovers(v.terms, cart, v.periodSpent, v.totalSpent)
        covered = cv
        if (!cv.ok && cv.reason != "over_limit" && cv.reason != "out_of_scope") return deny("mandate_${cv.reason}")
    } else if (merchantPolicy.requireMandate) reasons += "mandate_required"
    if (merchantPolicy.requireOwner && owner == null) reasons += "owner_unknown"
    if (reasons.isNotEmpty()) return deny(*reasons.toTypedArray())

    // Per-cart approval: needed when there is no mandate, the mandate does not cover the cart, or the cart is over step_up_over.
    if (covered != null && covered.ok && !covered.stepUpRequired) return CheckoutDecision("allow", listOf("mandate_covers_cart"), evidence)
    val why = if (covered == null) "no_mandate" else if (!covered.ok) "mandate_${covered.reason}" else "step_up_over"
    if (approval != null && keyLog != null && owner != null) {
        try {
            val a = verifyApproval(
                approval.approval, keyLog, approval.verifierDid, owner, approval.requestId, cartDigest(cart), now,
                decisions = listOf("approve"), origins = origins, counter = approval.counter,
            )
            evidence["approval_request_id"] = approval.requestId
            evidence["approval_kid"] = a.kid
            evidence["approval_counter"] = a.counter
            return CheckoutDecision("allow", listOf("owner_approved_cart", why), evidence)
        } catch (e: OpenEntityException) {
            evidence["approval_error"] = e.code
        }
    }
    return CheckoutDecision("step_up", listOf(why), evidence)
}
