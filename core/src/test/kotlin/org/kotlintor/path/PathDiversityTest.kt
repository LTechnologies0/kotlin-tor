package org.kotlintor.path

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.kotlintor.config.TorConfig
import org.kotlintor.config.TorrcParser
import org.kotlintor.dir.GeoIp
import org.kotlintor.dir.RouterStatus
import java.nio.file.Path

class PathDiversityTest {
    @Test
    fun `continent mapping covers major codes`() {
        assertEquals(GeoRegion.Continent.EU, GeoRegion.continentOf("de"))
        assertEquals(GeoRegion.Continent.NA, GeoRegion.continentOf("US"))
        assertEquals(GeoRegion.Continent.AS, GeoRegion.continentOf("jp"))
        assertEquals(GeoRegion.Continent.UNKNOWN, GeoRegion.continentOf(null))
        assertEquals(GeoRegion.Continent.UNKNOWN, GeoRegion.continentOf("zz"))
    }

    @Test
    fun `same country middle rejected when GeoIP present`(@TempDir dir: Path) {
        val geo = GeoIp.parseTorFormat(
            """
            ${ipToInt("1.0.0.1")},${ipToInt("1.0.0.255")},de
            ${ipToInt("2.0.0.1")},${ipToInt("2.0.0.255")},fr
            ${ipToInt("3.0.0.1")},${ipToInt("3.0.0.255")},us
            ${ipToInt("4.0.0.1")},${ipToInt("4.0.0.255")},jp
            """.trimIndent(),
        )
        val config = TorConfig(
            dataDirectory = dir,
            enforceDistinctCountries = true,
            enforceDistinctContinents = false,
            circuitAvoidRecentHops = false,
            useEntryGuards = false,
        )
        val sel = PathSelector(config, dir.resolve("guards")).also { it.geoIp = geo }
        val g = hop("1111111111111111111111111111111111111111", "1.0.0.10", guard = true)
        val mSame = hop("2222222222222222222222222222222222222222", "1.0.0.20", middle = true)
        val mOk = hop("3333333333333333333333333333333333333333", "2.0.0.20", middle = true)
        val eOk = hop("4444444444444444444444444444444444444444", "3.0.0.20", exit = true)
        val eJp = hop("5555555555555555555555555555555555555555", "4.0.0.20", exit = true)
        repeat(30) {
            val path = sel.select(listOf(g, mSame, mOk, eOk, eJp))
            assertEquals(g.fingerprintHex, path.guard.fingerprintHex)
            assertNotEquals(mSame.fingerprintHex, path.middle.fingerprintHex)
            assertEquals(mOk.fingerprintHex, path.middle.fingerprintHex)
            assertTrue(path.exit.fingerprintHex in setOf(eOk.fingerprintHex, eJp.fingerprintHex))
        }
    }

    @Test
    fun `same continent rejected when enabled`(@TempDir dir: Path) {
        val geo = GeoIp.parseTorFormat(
            """
            ${ipToInt("10.0.0.1")},${ipToInt("10.0.0.255")},de
            ${ipToInt("11.0.0.1")},${ipToInt("11.0.0.255")},fr
            ${ipToInt("12.0.0.1")},${ipToInt("12.0.0.255")},us
            ${ipToInt("13.0.0.1")},${ipToInt("13.0.0.255")},br
            """.trimIndent(),
        )
        val config = TorConfig(
            dataDirectory = dir,
            enforceDistinctCountries = true,
            enforceDistinctContinents = true,
            circuitAvoidRecentHops = false,
            useEntryGuards = false,
        )
        val sel = PathSelector(config, dir.resolve("guards")).also { it.geoIp = geo }
        val g = hop("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "10.0.0.10", guard = true)
        val mEu = hop("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "11.0.0.10", middle = true)
        val mNa = hop("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", "12.0.0.10", middle = true)
        val eSa = hop("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", "13.0.0.10", exit = true)
        repeat(20) {
            val path = sel.select(listOf(g, mEu, mNa, eSa))
            assertEquals(mNa.fingerprintHex, path.middle.fingerprintHex)
            assertEquals(eSa.fingerprintHex, path.exit.fingerprintHex)
        }
    }

    @Test
    fun `recent middle exit avoided then cleared`(@TempDir dir: Path) {
        val config = TorConfig(
            dataDirectory = dir,
            circuitAvoidRecentHops = true,
            circuitRecentHopHistorySize = 64,
            enforceDistinctCountries = false,
            enforceDistinctContinents = false,
            useEntryGuards = false,
        )
        val sel = PathSelector(config, dir.resolve("guards"))
        val g = hop("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "1.1.1.1", guard = true)
        val m1 = hop("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "2.2.2.2", middle = true)
        val m2 = hop("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", "3.3.3.3", middle = true)
        val e1 = hop("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", "4.4.4.4", exit = true)
        val e2 = hop("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE", "5.5.5.5", exit = true)
        val first = sel.select(listOf(g, m1, m2, e1, e2))
        assertTrue(sel.recentHopFingerprints().contains(first.middle.fingerprintHex.uppercase()))
        assertTrue(sel.recentHopFingerprints().contains(first.exit.fingerprintHex.uppercase()))
        val second = sel.select(listOf(g, m1, m2, e1, e2))
        assertNotEquals(first.middle.fingerprintHex, second.middle.fingerprintHex)
        assertNotEquals(first.exit.fingerprintHex, second.exit.fingerprintHex)
        sel.clearRecentHops()
        assertTrue(sel.recentHopFingerprints().isEmpty())
    }

    @Test
    fun `relax when only same-country candidates`(@TempDir dir: Path) {
        val geo = GeoIp.parseTorFormat(
            "${ipToInt("8.8.8.0")},${ipToInt("8.8.8.255")},de",
        )
        val config = TorConfig(
            dataDirectory = dir,
            enforceDistinctCountries = true,
            enforceDistinctContinents = true,
            circuitAvoidRecentHops = false,
            useEntryGuards = false,
        )
        val sel = PathSelector(config, dir.resolve("guards")).also { it.geoIp = geo }
        val g = hop("1111111111111111111111111111111111111111", "8.8.8.1", guard = true)
        val m = hop("2222222222222222222222222222222222222222", "8.8.8.2", middle = true)
        val e = hop("3333333333333333333333333333333333333333", "8.8.8.3", exit = true)
        // Must still build (fail-soft relax).
        val path = sel.select(listOf(g, m, e))
        assertEquals(g.fingerprintHex, path.guard.fingerprintHex)
        assertEquals(m.fingerprintHex, path.middle.fingerprintHex)
        assertEquals(e.fingerprintHex, path.exit.fingerprintHex)
    }

    @Test
    fun `sticky guards unchanged across selects`(@TempDir dir: Path) {
        val config = TorConfig(
            dataDirectory = dir,
            useEntryGuards = true,
            numEntryGuards = 3,
            circuitAvoidRecentHops = false,
            enforceDistinctCountries = false,
            enforceDistinctContinents = false,
        )
        val sel = PathSelector(config, dir.resolve("guards"))
        val relays = (1..8).map { i ->
            hop(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".replaceRange(0, 2, "%02X".format(i)),
                "10.0.$i.1",
                guard = true,
                bw = i * 10L,
            )
        } + listOf(
            hop("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "20.0.0.1", middle = true),
            hop("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", "30.0.0.1", exit = true),
            hop("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", "31.0.0.1", middle = true),
            hop("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE", "32.0.0.1", exit = true),
        )
        val first = sel.select(relays)
        val sample = sel.sampledGuards().toSet()
        repeat(10) {
            val p = sel.select(relays)
            assertTrue(p.guard.fingerprintHex in sample || sample.isEmpty())
        }
        assertTrue(sample.contains(first.guard.fingerprintHex) || sample.isNotEmpty())
    }

    @Test
    fun `torrc parses diversity options`(@TempDir dir: Path) {
        val text = """
            DataDirectory ${dir.toAbsolutePath()}
            EnforceDistinctCountries 0
            EnforceDistinctContinents 0
            CircuitAvoidRecentHops 0
            CircuitRecentHopHistorySize 12
        """.trimIndent()
        val cfg = TorrcParser.parse(text, dir)
        assertFalse(cfg.enforceDistinctCountries)
        assertFalse(cfg.enforceDistinctContinents)
        assertFalse(cfg.circuitAvoidRecentHops)
        assertEquals(12, cfg.circuitRecentHopHistorySize)
    }

    @Test
    fun `recent hop avoider ttl and capacity`() {
        val a = RecentHopAvoider(capacity = 2, ttlMs = 1_000)
        a.record("aa", nowMs = 0)
        a.record("bb", nowMs = 0)
        a.record("cc", nowMs = 0)
        assertFalse(a.contains("aa", nowMs = 0))
        assertTrue(a.contains("bb", nowMs = 0))
        assertTrue(a.contains("cc", nowMs = 0))
        assertFalse(a.contains("bb", nowMs = 2_000))
    }

    private fun hop(
        fp: String,
        ip: String,
        guard: Boolean = false,
        middle: Boolean = false,
        exit: Boolean = false,
        bw: Long = 100,
    ): RouterStatus {
        val flags = buildSet {
            add("Running"); add("Fast"); add("Valid"); add("Stable")
            if (guard) add("Guard")
            if (exit) add("Exit")
            // Middles are non-exit non-only; guards without Exit can be middle pool.
            @Suppress("UNUSED_EXPRESSION")
            middle
        }
        return RouterStatus(
            nickname = "N${fp.take(6)}",
            identity = org.kotlintor.util.hexToBytes(fp),
            digest = ByteArray(20),
            publication = java.time.Instant.EPOCH,
            ip = ip,
            orPort = 9001,
            dirPort = 0,
            flags = flags,
            version = null,
            proto = emptyMap(),
            bandwidth = bw,
        )
    }

    private fun ipToInt(dotted: String): Long {
        val p = dotted.split('.').map { it.toInt() }
        return (p[0].toLong() shl 24) or (p[1].toLong() shl 16) or (p[2].toLong() shl 8) or p[3].toLong()
    }
}
