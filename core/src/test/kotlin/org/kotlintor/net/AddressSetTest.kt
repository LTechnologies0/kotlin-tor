package org.kotlintor.net

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.InetAddress

class AddressSetTest {
    @Test
    fun `added address is found`() {
        val set = AddressSet(64)
        val a = InetAddress.getByName("1.2.3.4")
        set.add(a)
        assertTrue(set.probablyContains(a))
        // Different address may or may not collide; just ensure add works.
        set.addIpv4HostOrder(0x01020304)
        assertTrue(set.probablyContains(InetAddress.getByName("1.2.3.4")))
    }

    @Test
    fun `fresh set misses unrelated`() {
        val set = AddressSet.of("8.8.8.8")
        // Not a hard guarantee for bloom, but empty-ish other should usually miss.
        val other = InetAddress.getByName("9.9.9.9")
        // May false-positive; only assert known member.
        assertTrue(set.probablyContains(InetAddress.getByName("8.8.8.8")))
        // Force check that we don't claim empty set contains everything:
        val empty = AddressSet(32)
        assertFalse(empty.probablyContains(other))
    }

    @Test
    fun `ipv6 and clear`() {
        val set = AddressSet(64)
        val v6 = InetAddress.getByName("2001:db8::1")
        set.add(v6)
        assertTrue(set.probablyContains(v6))
        set.clear()
        assertFalse(set.probablyContains(v6))
    }
}
