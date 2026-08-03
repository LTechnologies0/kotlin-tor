package org.kotlintor.elevate

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.kotlintor.config.TorrcParser
import org.kotlintor.dir.AuthorityCert
import org.kotlintor.dir.DirAuthPeerNetwork
import org.kotlintor.dir.DirAuthorityConfig
import java.nio.file.Path

class StatsHsDirAuthElevationTest {
    @Test
    fun `typed Stats HS Guard DirAuthority options`() {
        val cfg = TorrcParser.parse(
            """
            DataDirectory /tmp/kt
            CellStatistics 1
            EntryStatistics 1
            DirReqStatistics 1
            HiddenServiceStatistics 1
            ConnDirectionStatistics 1
            ExtraInfoStatistics 0
            GuardLifetime 30
            NumDirectoryGuards 5
            GuardsKeepDesc 0
            FetchHidServDescriptors 0
            FetchServerDescriptors 0
            ClientDNSRejectInternalAddresses 0
            UseDefaultFallbackDirs 0
            DirAuthority testauth orport=9001 v3ident=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 127.0.0.1:9030
            HiddenServiceDir /tmp/kt/hs
            HiddenServicePort 80 127.0.0.1:8080
            HiddenServiceNumIntroductionPoints 5
            HiddenServiceMaxStreams 10
            HiddenServiceMaxStreamsCloseCircuit 1
            HiddenServiceEnableIntroDoSDefense 1
            HiddenServiceEnableIntroDoSBurstPerSec 100
            HiddenServiceEnableIntroDoSRatePerSec 10
            HiddenServicePoWQueueBurst 50
            HiddenServiceVersion 3
            HiddenServiceOnionBalanceInstance 1
            """.trimIndent(),
            Path.of("/tmp/kt"),
        )
        assertTrue(cfg.statsOptions.cellStatistics)
        assertTrue(cfg.statsOptions.entryStatistics)
        assertTrue(cfg.statsOptions.dirReqStatistics)
        assertTrue(cfg.statsOptions.hiddenServiceStatistics)
        assertTrue(cfg.statsOptions.connDirectionStatistics)
        assertFalse(cfg.statsOptions.extraInfoStatistics)
        assertEquals(30L, cfg.guardLifetimeDays)
        assertEquals(5, cfg.numDirectoryGuards)
        assertFalse(cfg.guardsKeepDesc)
        assertFalse(cfg.fetchHidServDescriptors)
        assertFalse(cfg.fetchServerDescriptors)
        assertFalse(cfg.clientDnsRejectInternalAddresses)
        assertEquals(1, cfg.dirAuthorities.size)
        assertEquals("testauth", cfg.dirAuthorities[0].nickname)
        assertEquals(9030, cfg.dirAuthorities[0].dirPort)
        assertEquals(1, cfg.hiddenServices.size)
        val hs = cfg.hiddenServices[0]
        assertEquals(5, hs.numIntroductionPoints)
        assertEquals(10, hs.maxStreams)
        assertTrue(hs.maxStreamsCloseCircuit)
        assertTrue(hs.introDosDefense)
        assertEquals(100, hs.introDosBurstPerSec)
        assertEquals(10, hs.introDosRatePerSec)
        assertEquals(50, hs.powQueueBurst)
        assertTrue(hs.onionBalanceInstance)
    }

    @Test
    fun `DirAuthorityConfig parse FallbackDir`() {
        val fb = DirAuthorityConfig.parseFallbackDir(
            "1.2.3.4:9001 orport=9001 id=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        )
        requireNotNull(fb)
        assertEquals("1.2.3.4", fb.address)
        assertEquals(9001, fb.orPort)
    }

    @Test
    fun `DirAuthPeerNetwork three authorities reach quorum`(@TempDir dir: Path) = runBlocking {
        val auths = List(3) { AuthorityCert.generate(bits = 1024) }
        val net = DirAuthPeerNetwork(auths, dir)
        val result = net.runQuorumRound()
        assertTrue(result.votesExchanged >= 6, "votes=${result.votesExchanged}")
        assertTrue(result.signaturesExchanged >= 6, "sigs=${result.signaturesExchanged}")
        assertTrue(result.quorum, "expected quorum with 3/3 sigs")
        assertTrue(result.mergedSignatures >= 3)
        assertTrue(result.attachedConsensus!!.contains("directory-signature"))
    }
}
