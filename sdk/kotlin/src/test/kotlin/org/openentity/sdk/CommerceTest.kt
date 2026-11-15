package org.openentity.sdk

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

private val STATES = vector("approval-2.0/vectors.json")["key_states"]!!
private val MANDATES = vector("mandate-1/vectors.json")
private val CARTS = vector("cart-1/vectors.json")
private val RECEIPTS = vector("receipt-1/vectors.json")
private val CHECKOUT = vector("checkout-1/vectors.json")

private fun keys(name: String): OwnerKeys {
    val s = STATES[name]!!
    return object : OwnerKeys {
        override val did = s["did"].text()
        override val root = s["root"]?.let { Credential.fromJson(it) }
        override val approvers = s["approvers"].items().map { Credential.fromJson(it) }
        override val closed = s["closed"] == JsonValue.Bool(true)
    }
}

private fun JsonValue?.opt(k: String) = this[k]?.takeIf { it != JsonValue.Null }
private fun seed(from: Int) = ByteArray(32) { (it + from).toByte() }
private fun terms(name: String) = MandateTerms.fromJson(CARTS["mandates"][name]!!)
private fun parties(v: JsonValue?) = v.items().map { p -> Party.entries.first { it.wire == p.text() } }

private fun termsJson(t: MandateTerms) = mapOf(
    "currency" to t.limits.currency, "per_tx_max" to t.limits.perTxMax, "period" to t.limits.period, "period_max" to t.limits.periodMax, "total_max" to t.limits.totalMax,
)

@RunWith(Parameterized::class)
class MandateVectorTest(private val name: String, private val case: JsonValue) {
    companion object {
        @JvmStatic
        @Parameterized.Parameters(name = "{0}")
        fun cases() = MANDATES["cases"].items().map { arrayOf(it["name"].text(), it) }
    }

    @Test
    fun matchesExpect() {
        val x = case["context"]
        val r = verifyMandate(case["mandate"]!!, keys(x["key_state"].text()), x.opt("agent_did")?.text(), x["now"].long(), x.opt("status"))
        val got = when (r) {
            is MandateResult.Ok -> buildMap<String, Any?> {
                put("ok", true); put("mandate_id", r.terms.mandateId); put("limits", termsJson(r.terms)); put("kid", r.kid)
                put("scope", buildMap { put("merchants", r.terms.scope.merchants); r.terms.scope.categories?.let { put("categories", it) }; put("rails", r.terms.scope.rails) })
                put("step_up_over", r.terms.stepUpOver)
                r.periodSpent?.let { put("period_spent", it) }; r.totalSpent?.let { put("total_spent", it) }
            }.let { m -> if ("kid" in (case["expect"] as JsonValue.Obj).fields) m else m - "kid" }
            is MandateResult.Err -> mapOf("ok" to false, "error" to r.error)
        }
        assertEquals("$name: ${(r as? MandateResult.Err)?.message}", canonicalize(case["expect"]!!), canonicalize(json(got)))
    }
}

class CommerceTest {
    private fun mandatePool(): Map<String, JsonValue> {
        val pool = LinkedHashMap<String, JsonValue>()
        for (m in (CARTS["mandates"] as JsonValue.Obj).fields.values + MANDATES["cases"].items().map { it["mandate"]!! }) pool.putIfAbsent(m["mandate_id"].text(), m) // the tampered case reuses an id: the first is the real one
        return pool
    }

    @Test
    fun mandateDigestsAndReplay() {
        val pool = mandatePool()
        for (d in MANDATES["digests"].items()) assertEquals(d["digest"].text(), hex(mandateDigest(pool.getValue(d["mandate_id"].text()))))
        val r = MANDATES["replay"]["mandate_signature_as_approval"]!!
        val c = r["context"]
        expectCode(r["expect"]["error"].text()) {
            verifyApproval(r["approval"]!!, keys(c["key_state"].text()), c["verifier_did"].text(), c["owner_did"].text(), c["request_id"].text(), c["payload_digest"].text(), c["now"].long())
        }
    }

    @Test
    fun cartDigests() {
        for (c in CARTS["carts"].items()) {
            assertEquals(c["canonical"].text(), canonicalize(c["cart"]!!))
            assertEquals(c["digest"].text(), cartDigest(c["cart"]!!))
        }
        for (c in CARTS["invalid"].items()) assertThrows(IllegalArgumentException::class.java) { cartDigest(c["cart"]!!) }
    }

    @Test
    fun covers() {
        for (c in CARTS["covers"].items()) {
            val sp = c.opt("spent")
            val r = mandateCovers(terms(c["mandate"].text()), c["cart"]!!, sp?.get("period_spent")?.long(), sp?.get("total_spent")?.long())
            val got = buildMap<String, Any> { put("ok", r.ok); put("step_up_required", r.stepUpRequired); r.reason?.let { put("reason", it) } }
            assertEquals(c["name"].text(), canonicalize(c["expect"]!!), canonicalize(json(got)))
        }
    }

    @Test
    fun wildcardMerchantMatchesOnlyAPlainHostname() {
        val m = terms("M")
        val cart = CARTS["covers"].items()[0]["cart"] as JsonValue.Obj
        fun at(merchant: String) = mandateCovers(m, JsonValue.Obj(cart.fields + ("merchant" to JsonValue.Str(merchant))))
        assertTrue(at("did:web:shop.moltbotden.com").ok && at("did:web:shop.moltbotden.com%3A8443").ok)
        for (evil in listOf("did:web:evil.com%2F.moltbotden.com", "did:web:evil.com%23.moltbotden.com", "did:web:evil.com%3F.moltbotden.com", "did:web:evil.com%40.moltbotden.com", "did:web:%zz.moltbotden.com", "did:web:%ff.moltbotden.com", "did:web:evil.com%2")) {
            assertEquals(evil, "out_of_scope", at(evil).reason)
        }
    }

    @Test
    fun spentThatIsNegativeNeverFits() {
        val cart = CARTS["covers"].items()[0]["cart"]!!
        assertEquals("over_limit", mandateCovers(terms("M"), cart, periodSpent = -1000).reason)
        assertEquals("over_limit", mandateCovers(terms("M"), cart, totalSpent = -1).reason)
    }

    @Test
    fun statusWithUnicodeSpaceIsMalformed() {
        val m = MANDATES["cases"].items()[0]["mandate"] as JsonValue.Obj
        fun err(status: String) = mandateFieldsError(JsonValue.Obj(m.fields + ("status" to JsonValue.Str(status))))
        assertEquals(null, err("https://a.example/x"))
        for (sp in listOf(" ", "\u00a0", "\u2028", "\u3000", "\ufeff")) assertEquals("status must be an https URL", err("https://a.example/${sp}x"))
    }

    @Test
    fun spentThatWrapsNeverFits() {
        val cart = CARTS["covers"].items()[0]["cart"]!!
        assertEquals("over_limit", mandateCovers(terms("M"), cart, periodSpent = Long.MAX_VALUE).reason)
        assertEquals("over_limit", mandateCovers(terms("M"), cart, totalSpent = Long.MAX_VALUE).reason)
    }

    @Test
    fun aMalformedOrForeignStatusAnswerIsNoAnswer() {
        val c = MANDATES["cases"].items()[0]
        val x = c["context"]
        fun run(status: JsonValue) = verifyMandate(c["mandate"]!!, keys(x["key_state"].text()), x["agent_did"].text(), x["now"].long(), status)
        for (bad in listOf("{}", """{"status":"bogus"}""", """{"status":"active","mandate_id":"md_aaaaaaaaaaaaaaaaaaaaaaaaaa"}""", """{"status":"active","total_spent":"abc"}""", """{"status":"active","period_spent":-1}""", "\"active\"")) {
            assertEquals(bad, "status_required", (run(JsonValue.parse(bad)) as MandateResult.Err).error)
        }
        assertTrue(run(JsonValue.parse("""{"status":"active","mandate_id":"${c["mandate"]["mandate_id"].text()}"}""")) is MandateResult.Ok)
    }

    @Test
    fun receipts() {
        for (c in RECEIPTS["cases"].items()) {
            val r = verifyReceipt(c["receipt"]!!, require = c["require"]?.let { parties(it) } ?: listOf(Party.MERCHANT))
            val got = when (r) {
                is ReceiptResult.Ok -> mapOf("ok" to true, "signed_by" to r.signedBy.map { it.wire })
                is ReceiptResult.Err -> mapOf("ok" to false, "error" to r.error)
            }
            assertEquals("${c["name"].text()}: ${(r as? ReceiptResult.Err)?.message}", canonicalize(c["expect"]!!), canonicalize(json(got)))
        }
    }

    @Test
    fun signReceiptGuardsAndReproducesTheCommittedProof() {
        val base = RECEIPTS["cases"].items()[0]["receipt"] as JsonValue.Obj
        val bare = JsonValue.Obj(base.fields - "proofs")
        assertThrows(IllegalArgumentException::class.java) { signReceipt(bare, seed(77), Party.MERCHANT) } // not the merchant's key
        assertThrows(IllegalArgumentException::class.java) { signReceipt(JsonValue.Obj(bare.fields + ("total" to JsonValue.Num(1.5))), seed(0x21), Party.MERCHANT) }
        assertEquals("already signed by agent", assertThrows(IllegalArgumentException::class.java) { signReceipt(base, seed(1), Party.AGENT) }.message)
        // Ed25519 is deterministic: the committed merchant proof, byte for byte.
        val again = signReceipt(bare, seed(0x21), Party.MERCHANT, created = "2026-11-07T00:02:00Z")
        assertEquals(canonicalize(base["proofs"].items()[0]), canonicalize(again["proofs"].items()[0]))
        val both = signReceipt(again, seed(1), Party.AGENT, created = "2026-11-07T00:02:00Z")
        assertEquals(ReceiptResult.Ok(listOf(Party.MERCHANT, Party.AGENT)), verifyReceipt(both, require = listOf(Party.MERCHANT, Party.AGENT)))
        assertEquals("did:web signer needs its verificationMethod", true, assertThrows(IllegalArgumentException::class.java) {
            signReceipt(JsonValue.Obj(bare.fields + ("merchant_did" to JsonValue.Str("did:web:shop.example"))), seed(0x21), Party.MERCHANT)
        }.message!!.contains("verificationMethod"))
    }

    @Test
    fun receiptPartiesDifferAndRefundsStayInsideThePurchase() {
        val p = RECEIPTS["cases"].items()[0]["receipt"] as JsonValue.Obj
        assertTrue(receiptError(JsonValue.Obj(p.fields + ("merchant_did" to p["agent_did"]!!)))!!.contains("differ"))
        fun refund(id: String, total: Int, extra: Map<String, JsonValue> = emptyMap()) =
            JsonValue.Obj(p.fields - "proofs" + mapOf("kind" to JsonValue.Str("refund"), "receipt_id" to JsonValue.Str(id), "refers_to" to p["receipt_id"]!!, "total" to JsonValue.Num(total.toDouble())) + extra)
        val r1 = refund("rc_" + "a".repeat(26), 600)
        val r2 = refund("rc_" + "b".repeat(26), 400)
        assertEquals(ChainResult.Ok(1000), verifyReceiptChain(p, listOf(r1, r2)))
        assertEquals("over_refund", (verifyReceiptChain(p, listOf(r1, refund("rc_" + "b".repeat(26), 401))) as ChainResult.Err).error)
        assertEquals("mismatch", (verifyReceiptChain(p, listOf(r1, r1)) as ChainResult.Err).error)
        assertEquals("mismatch", (verifyReceiptChain(p, listOf(refund("rc_" + "a".repeat(26), 600, mapOf("currency" to JsonValue.Str("EUR"))))) as ChainResult.Err).error)
        assertEquals("mismatch", (verifyReceiptChain(p, listOf(refund("rc_" + "a".repeat(26), 600, mapOf("refers_to" to JsonValue.Str("rc_" + "c".repeat(26)))))) as ChainResult.Err).error)
        assertEquals("not_purchase", (verifyReceiptChain(r1, emptyList()) as ChainResult.Err).error)
    }

    private fun checkout(i: JsonValue, approvalCounter: Long = 0L): CheckoutDecision {
        val pol = i["merchant_policy"]
        val f = i.opt("agent")
        val a = i.opt("approval")
        return verifyAgentForCheckout(
            agentDid = i.opt("agent_did")?.text(), cart = i["cart"]!!, now = i["now"].long(),
            merchantPolicy = AgentPolicy(
                pol.opt("min_level")?.long()?.toInt(), pol["require_owner"] == JsonValue.Bool(true), pol["require_mandate"] == JsonValue.Bool(true),
                pol.opt("min_security_band")?.text(), pol.opt("accept_issuers")?.items()?.map { it.text() }.orEmpty(),
            ),
            agent = AgentFacts(f.opt("level")?.long()?.toInt(), f.opt("owner_did")?.text(), f.opt("security_band")?.text(), f.opt("security_issuer")?.text()),
            mandate = i.opt("mandate"), keyLog = keys(i["key_state"].text()), status = i.opt("status"),
            approval = a?.let { CheckoutApproval(it["approval"]!!, it["verifier_did"].text(), it["request_id"].text(), approvalCounter) },
        )
    }

    @Test
    fun checkoutVectors() {
        for (c in CHECKOUT["cases"].items()) {
            val r = checkout(c["input"]!!)
            val got = buildMap<String, Any> { put("decision", r.decision); put("reasons", r.reasons); r.evidence["approval_error"]?.let { put("approval_error", it) } }
            assertEquals(c["name"].text(), canonicalize(c["expect"]!!), canonicalize(json(got)))
        }
    }

    @Test
    fun anAllowByApprovalHandsBackTheKeyAndCounter() {
        val i = CHECKOUT["cases"].items().first { it["name"].text() == "allow-step-up-approved" }["input"]!!
        val r = checkout(i)
        assertEquals("allow", r.decision)
        assertEquals(i["approval"]["approval"]["device_id"].text(), r.evidence["approval_kid"])
        assertEquals(0L, r.evidence["approval_counter"])
    }

    @Test
    fun noVerifiedAgentIsNoCheckout() {
        val i = CHECKOUT["cases"].items()[0]["input"] as JsonValue.Obj
        val r = verifyAgentForCheckout(null, i["cart"]!!, AgentPolicy(), i["now"].long())
        assertEquals(listOf("request_unverified"), r.reasons)
    }

    private val agentDid = CHECKOUT["cases"].items()[0]["input"]["agent_did"].text()
    private val checkoutUrl = "https://shop.example/checkout"
    private val signed = signRequest("POST", checkoutUrl, ByteArray(0), seed(1), agentDid, 1_800_000_000L) // seed 1..32 is the entity throwaway key of keys.json

    private fun requestCheckout(request: CheckoutRequest, agent: String?, now: Long = 1_800_000_000L): CheckoutDecision {
        val first = CHECKOUT["cases"].items()[0]["input"]!!
        val cart = JsonValue.Obj((first["cart"] as JsonValue.Obj).fields + ("mandate_id" to JsonValue.Null))
        return verifyAgentForCheckout(agent, cart, AgentPolicy(), now, request = request)
    }

    @Test
    fun checkoutVerifiesTheSignedRequestItself() {
        val r = requestCheckout(CheckoutRequest("POST", checkoutUrl, signed), agent = "did:key:z6MkSomeoneElse") // the request's signer wins over agentDid
        assertEquals(listOf("no_mandate"), r.reasons)
        assertEquals("step_up", r.decision)
        assertEquals("verified", r.evidence["request"])
        assertEquals(agentDid, r.evidence["agent_did"])
    }

    @Test
    fun aBadRequestSignatureIsFinalEvenWithAnAgentDid() {
        for ((req, now) in listOf(
            CheckoutRequest("POST", "https://shop.example/other", signed) to 1_800_000_000L, // url tampered
            CheckoutRequest("POST", checkoutUrl, signed - "Signature") to 1_800_000_000L, // unsigned
            CheckoutRequest("POST", checkoutUrl, signed) to 1_800_001_000L, // stale
        )) {
            val d = requestCheckout(req, agent = agentDid, now = now)
            assertEquals("deny", d.decision)
            assertEquals(listOf("request_unverified"), d.reasons)
        }
    }
}
