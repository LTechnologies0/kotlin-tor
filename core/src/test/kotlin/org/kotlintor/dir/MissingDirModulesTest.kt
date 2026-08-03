package org.kotlintor.dir

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.util.hexToBytes

class MissingDirModulesTest {
    @Test
    fun `keypin conflict and journal`() {
        val j = Keypin.Journal()
        val rsa = hexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        val ed1 = ByteArray(32) { 1 }
        val ed2 = ByteArray(32) { 2 }
        assertEquals(Keypin.Result.ADDED, j.checkAndAdd(rsa, ed1))
        assertEquals(Keypin.Result.CONFLICT, j.checkAndAdd(rsa, ed2))
        assertEquals(Keypin.Result.REPLACED, j.checkAndAdd(rsa, ed2, replace = true))
        val text = j.formatJournal()
        val j2 = Keypin.Journal()
        j2.loadJournal(text)
        assertEquals(Keypin.Result.OK, j2.check(rsa, ed2))
    }

    @Test
    fun `consdiff generate apply roundtrip`() {
        val a = "network-status-version 3\nvote-status consensus\nr A AA 2020-01-01 00:00:00 1.1.1.1 9001 0\n"
        val b = "network-status-version 3\nvote-status consensus\nr B BB 2020-01-01 00:00:00 2.2.2.2 9001 0\n"
        val diff = ConsDiff.generate(a, b)
        assertTrue(ConsDiff.looksLikeDiff(diff))
        assertEquals(b, ConsDiff.apply(a, diff))
    }

    @Test
    fun `routerset nickname fingerprint cidr country`() {
        val rs = RouterSet.parse("Foo,\$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,1.2.3.0/24,{us}")
        assertTrue(rs.contains("Foo", null, null))
        assertTrue(rs.contains(null, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", null))
        assertTrue(rs.contains(null, null, "1.2.3.9"))
        assertTrue(rs.contains(null, null, null, "us"))
        assertFalse(rs.contains("Bar", null, "8.8.8.8", "de"))
    }

    @Test
    fun `dlstatus backoff`() {
        val d = DownloadStatus(minDelaySec = 1, maxDelaySec = 10)
        assertTrue(d.isReady(100))
        d.incrementFailure(100)
        assertFalse(d.isReady(100))
        assertTrue(d.nextAttemptAt >= 101)
    }

    @Test
    fun `geoip range lookup`() {
        // 1.2.3.0 = 0x01020300 = 16909056; 1.2.3.255 = 16909311
        val db = GeoIp.parseTorFormat("16909056,16909311,fr\n")
        assertEquals("fr", db.country("1.2.3.10"))
        assertEquals(null, db.country("8.8.8.8"))
    }
}
