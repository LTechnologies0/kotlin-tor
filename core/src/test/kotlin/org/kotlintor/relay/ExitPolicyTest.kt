package org.kotlintor.relay

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.InetAddress

class ExitPolicyTest {
    @Test
    fun `reject all by default`() {
        val p = ExitPolicy.rejectAll()
        assertFalse(p.allows(InetAddress.getByName("1.2.3.4"), 80))
    }

    @Test
    fun `first match wins`() {
        val p = ExitPolicy.fromTorrcLines(
            listOf(
                "reject 1.2.3.4:80",
                "accept *:80",
                "reject *:*",
            ),
        )
        assertFalse(p.allows(InetAddress.getByName("1.2.3.4"), 80))
        assertTrue(p.allows(InetAddress.getByName("8.8.8.8"), 80))
        assertFalse(p.allows(InetAddress.getByName("8.8.8.8"), 443))
    }

    @Test
    fun `cidr and port range`() {
        val p = ExitPolicy.fromTorrcLines(
            listOf("accept 192.168.0.0/16:8000-9000", "reject *:*"),
        )
        assertTrue(p.allows(InetAddress.getByName("192.168.1.10"), 8080))
        assertFalse(p.allows(InetAddress.getByName("192.168.1.10"), 80))
        assertFalse(p.allows(InetAddress.getByName("10.0.0.1"), 8080))
    }

    @Test
    fun `reduced policy allows https rejects random`() {
        val p = ExitPolicy.reduced()
        assertTrue(p.allows(InetAddress.getByName("8.8.8.8"), 443))
        assertTrue(p.allows(InetAddress.getByName("8.8.8.8"), 80))
        assertFalse(p.allows(InetAddress.getByName("8.8.8.8"), 25))
        assertFalse(p.allows(InetAddress.getByName("8.8.8.8"), 666))
    }
}
