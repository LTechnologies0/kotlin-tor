package org.kotlintor.net

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PrivateAddressesTest {
    @Test
    fun `IP literals are classified without treating hostnames as addresses`() {
        assertTrue(PrivateAddresses.isIpLiteral("127.0.0.1"))
        assertTrue(PrivateAddresses.isIpLiteral("10.0.0.1"))
        assertTrue(PrivateAddresses.isIpLiteral("8.8.8.8"))
        assertTrue(PrivateAddresses.isIpLiteral("::1"))
        assertTrue(PrivateAddresses.isIpLiteral("[2001:db8::1]"))
        assertFalse(PrivateAddresses.isIpLiteral("localhost"))
        assertFalse(PrivateAddresses.isIpLiteral("example.com"))
        assertFalse(PrivateAddresses.isIpLiteral("check.torproject.org"))
        assertFalse(PrivateAddresses.isIpLiteral(""))
    }

    @Test
    fun `private check does not DNS-resolve hostnames`() {
        assertTrue(PrivateAddresses.isPrivate("127.0.0.1"))
        assertTrue(PrivateAddresses.isPrivateLiteral("10.1.2.3"))
        assertTrue(PrivateAddresses.isPrivate("192.168.0.1"))
        assertFalse(PrivateAddresses.isPrivate("1.1.1.1"))
        // Hostname, even if it would resolve to loopback — no InetAddress.getByName.
        assertFalse(PrivateAddresses.isPrivate("localhost"))
        assertFalse(PrivateAddresses.isPrivateLiteral("example.com"))
        assertFalse(PrivateAddresses.isIpLiteral("localhost"))
        assertFalse(SafeSocksPolicy.isIpLiteral("localhost"))
        assertTrue(SafeSocksPolicy.allows("localhost", safeSocks = true))
        assertFalse(SafeSocksPolicy.allows("127.0.0.1", safeSocks = true))
        assertTrue(SafeSocksPolicy.allows("example.com", safeSocks = true))
    }
}
