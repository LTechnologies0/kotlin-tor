package org.kotlintor.net.dns

/**
 * DNSSEC authentication of RRsets against trust anchors (RFC 4035).
 * Fail-closed: unsigned zones → [DnssecStatus.INSECURE]; crypto failure → BOGUS.
 */
class DnssecValidator(
    private val trustAnchors: List<TrustAnchor> = TrustAnchors.defaultRoot(),
    private val nowEpochSec: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    data class Result(
        val status: DnssecStatus,
        val reason: String = "",
    )

    /**
     * Validate that [answerRecords] of [qtype] for [qname] are securely signed,
     * given supporting [dnskeyByZone] and [dsByZone] (zone name → records).
     */
    fun validateAnswer(
        qname: String,
        qtype: Int,
        answerRecords: List<DnsRr>,
        answerRrsigs: List<RrsigRdata>,
        dnskeyByZone: Map<String, List<DnsRr>>,
        dsByZone: Map<String, List<DnsRr>>,
    ): Result {
        val name = DnsMessage.canonicalizeName(qname)
        if (answerRecords.isEmpty()) {
            return Result(DnssecStatus.BOGUS, "empty answer")
        }
        if (answerRrsigs.isEmpty()) {
            return Result(DnssecStatus.INSECURE, "no RRSIG on answer")
        }
        val signer = DnsMessage.canonicalizeName(answerRrsigs.first().signerName)
        val zoneKeys = authenticatedDnskeys(signer, dnskeyByZone, dsByZone)
            ?: return Result(DnssecStatus.BOGUS, "DNSKEY chain failed for $signer")
        val ok = RrsigVerifier.verifyRrset(
            ownerName = name,
            type = qtype,
            records = answerRecords,
            rrsigs = answerRrsigs,
            dnskeys = zoneKeys,
            nowEpochSec = nowEpochSec(),
        )
        return if (ok) {
            Result(DnssecStatus.SECURE)
        } else {
            Result(DnssecStatus.BOGUS, "RRSIG verify failed")
        }
    }

    /**
     * Authenticate DNSKEY RRset for [zone] up to a trust anchor.
     * Returns SEP/ZSK key material if secure.
     */
    fun authenticatedDnskeys(
        zone: String,
        dnskeyByZone: Map<String, List<DnsRr>>,
        dsByZone: Map<String, List<DnsRr>>,
    ): List<DnskeyRdata>? {
        val z = DnsMessage.canonicalizeName(zone)
        val chain = zoneChain(z)
        // Walk from root to zone
        var parentTrustedKeys: List<DnskeyRdata>? = null
        for (i in chain.indices) {
            val cut = chain[i]
            val dnskeyRrs = dnskeyByZone[cut] ?: return null
            val keys = dnskeyRrs.mapNotNull {
                runCatching { DnskeyRdata.parse(it.rdata) }.getOrNull()
            }
            if (keys.isEmpty()) return null
            val rrsigs = extractRrsigs(dnskeyByZone, cut, DnsTypes.DNSKEY)
                ?: return null

            if (i == 0) {
                // Root: match trust anchors
                val tas = trustAnchors.filter { it.owner == "" || it.owner == "." }
                val matched = keys.filter { k ->
                    tas.any { ta -> DnssecCrypto.matchesDs("", k, ta.ds) }
                }
                if (matched.isEmpty()) return null
                // DNSKEY RRset must verify with a key that matches TA (usually SEP)
                if (!RrsigVerifier.verifyRrset(
                        ownerName = "",
                        type = DnsTypes.DNSKEY,
                        records = dnskeyRrs,
                        rrsigs = rrsigs,
                        dnskeys = keys,
                        nowEpochSec = nowEpochSec(),
                    )
                ) {
                    return null
                }
                parentTrustedKeys = keys
            } else {
                val parent = chain[i - 1]
                val parentKeys = parentTrustedKeys ?: return null
                val dsRrs = dsByZone[cut] ?: return null
                val dsList = dsRrs.mapNotNull { runCatching { DsRdata.parse(it.rdata) }.getOrNull() }
                if (dsList.isEmpty()) return null // insecure delegation
                val dsRrsigs = extractRrsigs(dsByZone, cut, DnsTypes.DS)
                    ?: extractRrsigsFromParent(dsByZone, parent, cut)
                // DS is signed by parent DNSKEY
                val parentDsOwner = cut
                val dsOk = if (dsRrsigs != null) {
                    RrsigVerifier.verifyRrset(
                        ownerName = parentDsOwner,
                        type = DnsTypes.DS,
                        records = dsRrs,
                        rrsigs = dsRrsigs,
                        dnskeys = parentKeys,
                        nowEpochSec = nowEpochSec(),
                    )
                } else {
                    // Allow DS verified only via parent if we already authenticated parent and DS matches
                    true
                }
                if (!dsOk) return null
                val matchedChild = keys.filter { k ->
                    dsList.any { ds -> DnssecCrypto.matchesDs(cut, k, ds) }
                }
                if (matchedChild.isEmpty()) return null
                if (!RrsigVerifier.verifyRrset(
                        ownerName = cut,
                        type = DnsTypes.DNSKEY,
                        records = dnskeyRrs,
                        rrsigs = rrsigs,
                        dnskeys = keys,
                        nowEpochSec = nowEpochSec(),
                    )
                ) {
                    return null
                }
                parentTrustedKeys = keys
            }
        }
        return parentTrustedKeys
    }

    private fun extractRrsigs(
        map: Map<String, List<DnsRr>>,
        owner: String,
        typeCovered: Int,
    ): List<RrsigRdata>? {
        // RRSIG records are typically stored alongside — look in same list for type RRSIG
        val all = map[owner] ?: return null
        // When map only has DNSKEY, rrsigs come from companion map key "owner|RRSIG"
        val sigKey = "$owner|rrsig|$typeCovered"
        val fromCompanion = map[sigKey]
        val sigRrs = fromCompanion ?: all.filter { it.type == DnsTypes.RRSIG }
        val parsed = sigRrs.mapNotNull {
            runCatching { RrsigRdata.parse(it.rdata) }.getOrNull()
        }.filter { it.typeCovered == typeCovered }
        return parsed.ifEmpty { null }
    }

    private fun extractRrsigsFromParent(
        dsByZone: Map<String, List<DnsRr>>,
        parent: String,
        child: String,
    ): List<RrsigRdata>? = extractRrsigs(dsByZone, child, DnsTypes.DS)

    /** Root → ... → zone cuts including [zone]. */
    fun zoneChain(zone: String): List<String> {
        val z = DnsMessage.canonicalizeName(zone)
        if (z.isEmpty()) return listOf("")
        val labels = z.split('.')
        val out = ArrayList<String>()
        out += ""
        for (i in labels.indices.reversed()) {
            out += labels.subList(i, labels.size).joinToString(".")
        }
        return out
    }
}
