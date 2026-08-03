package org.kotlintor.dir

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.compress.CompressMethod
import org.kotlintor.compress.TorCompress
import org.kotlintor.net.AutomapAddressMap
import org.kotlintor.net.DnsResolveCache
import org.kotlintor.path.PathBiasTracker
import org.kotlintor.stats.ConnStats
import org.kotlintor.stats.GeoIpStats
import org.kotlintor.stats.HsStats
import java.nio.file.Files
import java.util.Base64

class RemainingGapsElevationTest {
    @Test
    fun `recommend pkg validate`() {
        assertTrue(RecommendPkg.validate("tor 0.4.8.0 https://example.com sha256=abcdef"))
        assertFalse(RecommendPkg.validate("tor 0.4.8.0 https://example.com"))
        assertFalse(RecommendPkg.validate("tor 0.4.8.0 https://example.com =bad"))
    }

    @Test
    fun `bridgeauth dump`() {
        val body = BridgeAuth.formatNetworkstatusBridges(
            listOf(
                BridgeAuth.BridgeStatus(
                    identityHex = "aa".repeat(20),
                    nickname = "br1",
                    ip = "1.2.3.4",
                    orPort = 443,
                    flags = setOf("Running", "V2Dir"),
                    bandwidthKb = 100,
                ),
            ),
            fingerprintHex = "bb".repeat(20),
        )
        assertTrue(body.contains("published "))
        assertTrue(body.contains("fingerprint "))
        val dir = Files.createTempDirectory("ktor-ba")
        val f = BridgeAuth.dumpToFile(dir, body)
        assertTrue(Files.readString(f).startsWith("published"))
    }

    @Test
    fun `shared random client parse`() {
        val srv = ByteArray(32) { 7 }
        val b64 = Base64.getEncoder().encodeToString(srv)
        val ns = """
            network-status-version 3
            shared-rand-previous-value 3 $b64
            shared-rand-current-value 5 $b64
        """.trimIndent()
        val (cur, prev) = SharedRandomClient.parseFromConsensus(ns)
        assertNotNull(cur)
        assertEquals(5, cur!!.numReveals)
        assertEquals(3, prev!!.numReveals)
        assertTrue(SharedRandomClient.protocolRunDurationSec() > 0)
    }

    @Test
    fun `consdiff mgr`() {
        val mgr = ConsDiffMgr()
        val a = "network-status-version 3\nfoo\n"
        val b = "network-status-version 3\nbar\n"
        mgr.storeDiff(a, b)
        val applied = mgr.applyCached(a, ConsDiff.sha3Hex(b))
        assertEquals(b, applied)
    }

    @Test
    fun `consdiff mgr disk persist`() {
        val dir = Files.createTempDirectory("ktor-cdm")
        val a = "network-status-version 3\nold\n"
        val b = "network-status-version 3\nnew\n"
        ConsDiffMgr(storeDir = dir).storeDiff(a, b)
        val reloaded = ConsDiffMgr(storeDir = dir)
        assertEquals(b, reloaded.applyCached(a, ConsDiff.sha3Hex(b)))
    }

    @Test
    fun `compress gzip roundtrip and negotiate`() {
        val raw = "hello consensus document ".repeat(20).toByteArray()
        val gz = TorCompress.compress(raw, CompressMethod.GZIP)
        assertEquals(CompressMethod.GZIP, TorCompress.detect(gz))
        assertEquals(String(raw), String(TorCompress.uncompress(gz)))
        assertEquals(CompressMethod.GZIP, TorCompress.negotiate("gzip, deflate"))
        // ZSTD is registered when zstd-jni is on the classpath.
        assertEquals(
            TorCompress.provider(CompressMethod.ZSTD) != null,
            TorCompress.supports(CompressMethod.ZSTD),
        )
    }

    @Test
    fun `conn geo hs stats`() {
        ConnStats.init()
        ConnStats.noteOrConnBytes(1, 10, 20)
        assertTrue(ConnStats.format().contains("conn-bi-direct"))
        GeoIpStats.reset()
        GeoIpStats.noteClientSeen(GeoIpStats.ClientAction.CONNECT, "8.8.8.8")
        GeoIpStats.noteNsResponse(GeoIpStats.NsResponse.SUCCESS)
        assertTrue(GeoIpStats.formatEntryStats().contains("entry-stats-end"))
        HsStats.reset()
        HsStats.enabled = true
        HsStats.noteIntroduce2Cell()
        HsStats.noteServiceRendezvousLaunch()
        assertEquals(1, HsStats.nIntroduce2V3Cells())
        assertEquals(1, HsStats.nRendezvousLaunches())
    }

    @Test
    fun `automap and dns cache`() {
        val am = AutomapAddressMap()
        assertTrue(am.shouldAutomap("abc.onion"))
        val ip = am.getOrAssign("abc.onion")
        assertEquals("abc.onion", am.reverse(ip))
        val dns = DnsResolveCache(ttlSec = 60)
        dns.put("example.com", listOf("1.2.3.4"))
        assertEquals(listOf("1.2.3.4"), dns.get("example.com"))
    }

    @Test
    fun `pathbias drop guards`() {
        val t = PathBiasTracker(minCircs = 2, dropGuards = true)
        t.markBuildAttempted(1, "aa")
        t.markBuildAttempted(2, "aa")
        // 0 successes → extreme
        assertEquals(PathBiasTracker.Level.EXTREME, t.assess("aa"))
        assertTrue(t.isGuardDisabled("aa"))
    }

    @Test
    fun `torrc accounting and automap typed`() {
        val cfg = org.kotlintor.config.TorrcParser.parse(
            """
            DataDirectory /tmp/ktor-x
            AccountingMax 1 MB
            PathBiasDropGuards 1
            AutomapHostsOnResolve 1
            VirtualAddrNetworkIPv4 127.192.0.0/10
            GeoIPFile /tmp/geoip
            """.trimIndent(),
            java.nio.file.Path.of("/tmp/ktor-x"),
        )
        assertEquals(1_000_000L, cfg.accountingMaxBytes)
        assertTrue(cfg.pathBiasDropGuards)
        assertTrue(cfg.automapHostsOnResolve)
        assertNotNull(cfg.geoIpFile)
    }
}
