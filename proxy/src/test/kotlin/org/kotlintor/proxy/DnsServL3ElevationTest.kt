package org.kotlintor.proxy

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * Elevates dnsserv.h L3 ops (D2→D3) via OP_SEED_DEPTH.
 */
class DnsServL3ElevationTest {
    @BeforeEach
    fun reset() {
        DnsServ.resetForTests()
    }

    @Test
    fun `dnsserv listener request resolve reject`() {
        val l = DnsServ.dnsservConfigureListener("127.0.0.1", 5353)
        assertEquals(5353, l.port)
        assertTrue(DnsServ.isListening())

        val q = DnsServ.dnsservLaunchRequest("example.com")
        assertEquals("example.com", q.name)
        assertTrue(DnsServ.pendingRequests().contains(q))

        DnsServ.dnsservResolved(q, "93.184.216.34")
        assertTrue(DnsServ.resolvedAnswers().any { it.first == q && it.second == "93.184.216.34" })
        assertFalse(DnsServ.pendingRequests().contains(q))

        val bad = DnsServ.dnsservLaunchRequest("evil.example")
        DnsServ.dnsservRejectRequest(bad)
        assertTrue(DnsServ.rejectedRequests().contains(bad))

        DnsServ.dnsservCloseListener()
        assertFalse(DnsServ.isListening())
    }
}
