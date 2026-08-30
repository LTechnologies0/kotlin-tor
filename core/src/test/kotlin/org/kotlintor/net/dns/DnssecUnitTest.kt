package org.kotlintor.net.dns

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DnssecUnitTest {
    @Test
    fun parseQueryRoundTrip() {
        val q = DnsMessage.buildQuery("example.com", DnsTypes.A, id = 0x1234, dnssecOk = true)
        val p = DnsMessage.parse(q)
        assertEquals(0x1234, p.id)
        assertEquals(1, p.questions.size)
        assertEquals("example.com", p.questions[0].name)
        assertEquals(DnsTypes.A, p.questions[0].type)
        assertTrue(p.additionals.any { it.type == DnsTypes.OPT })
    }

    @Test
    fun keyTagKnownVector() {
        // Minimal synthetic DNSKEY — tag algorithm must be stable for same bytes
        val key = DnskeyRdata(
            flags = 256,
            protocol = 3,
            algorithm = DnsTypes.ALG_RSASHA256,
            publicKey = ByteArray(16) { it.toByte() },
        )
        val tag1 = DnssecCrypto.keyTag(key)
        val tag2 = DnssecCrypto.keyTag(key.toBytes())
        assertEquals(tag1, tag2)
    }

    @Test
    fun rootTrustAnchor2017Present() {
        val tas = TrustAnchors.defaultRoot()
        assertTrue(tas.any { it.ds.keyTag == 20326 && it.ds.digest.size == 32 })
        val bundled = TrustAnchors.load(null)
        assertTrue(bundled.any { it.ds.keyTag == 20326 })
    }

    @Test
    fun zoneChainIncludesRoot() {
        val v = DnssecValidator()
        assertEquals(listOf(""), v.zoneChain(""))
        assertEquals(listOf("", "com", "example.com"), v.zoneChain("example.com"))
    }

    @Test
    fun nsecCompareOrder() {
        assertTrue(NsecProofs.compareNames("a.example", "b.example") < 0)
        assertEquals(0, NsecProofs.compareNames("Example.COM", "example.com"))
    }

    @Test
    fun nsec3HashDeterministic() {
        val h1 = NsecProofs.nsec3Hash("example.com", ByteArray(0), 0)
        val h2 = NsecProofs.nsec3Hash("example.com", ByteArray(0), 0)
        assertTrue(h1.contentEquals(h2))
        assertEquals(20, h1.size)
    }

    @Test
    fun parseRecursiveEndpoint() {
        assertEquals("1.1.1.1" to 53, parseRecursiveEndpoint("1.1.1.1"))
        assertEquals("8.8.8.8" to 53, parseRecursiveEndpoint("8.8.8.8:53"))
        assertEquals("2001:db8::1" to 53, parseRecursiveEndpoint("[2001:db8::1]:53"))
    }

    @Test
    fun dnssecModeParse() {
        assertEquals(DnssecMode.OFF, DnssecMode.parse("off"))
        assertEquals(DnssecMode.VALIDATE, DnssecMode.parse("validate"))
        assertEquals(DnssecMode.VALIDATE, DnssecMode.parse("1"))
    }

    @Test
    fun insecureWithoutRrsigIsInsecure() {
        val v = DnssecValidator()
        val rr = DnsRr("example.com", DnsTypes.A, DnsTypes.CLASS_IN, 60, DnsMessage.aRdata("93.184.216.34"))
        val r = v.validateAnswer(
            qname = "example.com",
            qtype = DnsTypes.A,
            answerRecords = listOf(rr),
            answerRrsigs = emptyList(),
            dnskeyByZone = emptyMap(),
            dsByZone = emptyMap(),
        )
        assertEquals(DnssecStatus.INSECURE, r.status)
    }

    @Test
    fun ecdsaRawToDerRoundShape() {
        val raw = ByteArray(64) { (it + 1).toByte() }
        val der = RrsigVerifier.ecdsaRawToDer(raw)
        assertEquals(0x30.toByte(), der[0])
        assertTrue(der.size > 64)
    }

    @Test
    fun supportedAlgsOnly() {
        assertTrue(DnsTypes.supportedAlg(8))
        assertTrue(DnsTypes.supportedAlg(13))
        assertFalse(DnsTypes.supportedAlg(5)) // RSASHA1 rejected
        assertFalse(DnsTypes.supportedAlg(7))
    }
}
