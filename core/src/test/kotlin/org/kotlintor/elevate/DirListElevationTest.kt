package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.dir.DirList
import org.kotlintor.dir.DirServer

/**
 * Elevates `L1:feature/nodelist/dirlist.c` toward D3.
 *
 * Evidence: digest/addr trust helpers, dirport exact/legacy fallback, markAllUp.
 */
class DirListElevationTest {
    @Test
    fun `trusted and fallback digest helpers`() {
        val list = DirList()
        val auth = DirList.trustedDirServerNew(
            "Auth", "1.2.3.4", 80, 443,
            v3IdentityHex = "AA".repeat(20),
            identityHex = "BB".repeat(20),
        )
        list.add(auth)
        assertTrue(list.digestIsTrusted("BB".repeat(20)))
        assertFalse(list.digestIsTrusted("aa".repeat(20))) // v3 digest ≠ RSA trusted digest
        assertNotNull(list.trustedByV3Digest("aa".repeat(20)))
        assertTrue(list.digestIsFallback("BB".repeat(20))) // authorities in fallback view
        assertTrue(list.addrIsTrusted("1.2.3.4"))
        assertFalse(list.addrIsTrusted("9.9.9.9"))
        assertEquals(1, list.authorityCount())
    }

    @Test
    fun `dirport exact and legacy fallback`() {
        val ds = DirList.trustedDirServerNew("A", "1.1.1.1", 80, 443, "CC".repeat(20))
        ds.addDirport("upload", "1.1.1.1", 9030)
        ds.addDirport("legacy", "1.1.1.1", 80)
        ds.addDirport("upload", "2001:db8::1", 9030)
        assertEquals(9030, ds.getDirportExact("upload", preferIpv6 = false)?.second)
        assertEquals(9030, ds.getDirportExact("upload", preferIpv6 = true)?.second)
        assertNull(ds.getDirportExact("begin_dir"))
        assertEquals(80, ds.getDirport("begin_dir")?.second) // falls back to legacy
    }

    @Test
    fun `mark_all_dirservers_up and remove`() {
        val list = DirList.withDefaults()
        assertTrue(list.trusted().isNotEmpty())
        list.trusted().forEach { it.isRunning = false }
        list.markAllUp()
        assertTrue(list.trusted().all { it.isRunning })
        val id = list.trusted().first().v3IdentityHex
        assertNotNull(id)
        assertTrue(list.removeByIdentity(id!!))
        list.clearDirServers()
        assertEquals(0, list.size())
    }

    @Test
    fun `fallback_dir_server_new parse line`() {
        val list = DirList()
        val fb = DirList.fallbackDirServerNew("198.51.100.1", 80, 443, "DD".repeat(20), weight = 1.5)
        list.add(fb)
        assertTrue(list.digestIsFallback("dd".repeat(20)))
        assertFalse(list.digestIsTrusted("dd".repeat(20)))
        val parsed = list.parseFallbackLine(
            "198.51.100.2:80 orport=443 id=${"EE".repeat(20)} weight=2.0 nick",
        )
        assertNotNull(parsed)
        assertEquals(2.0, parsed!!.weight, 0.001)
    }
}
