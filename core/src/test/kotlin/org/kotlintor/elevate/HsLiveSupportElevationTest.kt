package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.dir.Consensus
import org.kotlintor.hs.HsCache
import org.kotlintor.hs.HsControl
import org.kotlintor.hs.HsDosDefense
import org.kotlintor.hs.HsIdentDirConn
import org.kotlintor.hs.HsIntroFsm
import org.kotlintor.hs.HsIntroPointTable
import org.kotlintor.hs.HsMetrics
import org.kotlintor.hs.HsOpts
import org.kotlintor.hs.HsSys
import org.kotlintor.config.HiddenServiceConfig
import org.kotlintor.config.HiddenServicePort
import org.kotlintor.config.TorConfig
import java.nio.file.Path
import java.time.Instant

/**
 * Elevates HS live-support rows D1→D2:
 * L1:feature/hs/hs_{dos,cache,intropoint,control,common,config,ident,metrics,metrics_entry,sys}.c
 */
class HsLiveSupportElevationTest {
    private val dataDir: Path = Path.of("/tmp/ktor-elevate-hs-live")

    @Test
    fun `hs_dos consensus params and reject counter`() {
        val dos = HsDosDefense()
        assertFalse(dos.enabled)
        assertTrue(dos.noteIntroduce("a")) // disabled → always admit
        val cons = Consensus(
            validAfter = Instant.EPOCH,
            freshUntil = Instant.EPOCH,
            validUntil = Instant.EPOCH,
            relays = emptyList(),
            raw = "",
            params = mapOf(
                "HiddenServiceEnableIntroDoSDefense" to 1L,
                "HiddenServiceEnableIntroDoSRatePerSec" to 1L,
                "HiddenServiceEnableIntroDoSBurstPerSec" to 2L,
            ),
        )
        dos.applyConsensus(cons)
        assertTrue(dos.enabled)
        assertEquals(1, dos.ratePerSec)
        assertEquals(2, dos.burst)
        assertTrue(dos.noteIntroduce("svc"))
        assertTrue(dos.noteIntroduce("svc"))
        assertFalse(dos.noteIntroduce("svc"))
        assertTrue(dos.rejectedCount() >= 1)
    }

    @Test
    fun `hs_intropoint FSM and hs_cache dirconn`() {
        val table = HsIntroPointTable()
        table.beginEstablish("ab")
        assertEquals(HsIntroFsm.ESTABLISHING, table.get("ab")?.fsm)
        table.noteEstablished("ab")
        table.noteIntroduce("ab")
        assertEquals(HsIntroFsm.INTRO_RECEIVED, table.get("AB")?.fsm)
        table.noteClosed("ab")
        assertEquals(HsIntroFsm.CLOSED, table.get("ab")?.fsm)

        val cache = HsCache()
        cache.noteDirConn(HsIdentDirConn("ff".repeat(32), "hint|1|0"))
        assertNotNull(cache.findDirConn("FF".repeat(32)))
        cache.clearDirConn("ff".repeat(32))
        assertEquals(null, cache.findDirConn("ff".repeat(32)))
    }

    @Test
    fun `hs_control gates and hs_config validate`() {
        assertTrue(HsControl.hsFetchAccepted("a".repeat(56) + ".onion"))
        assertFalse(HsControl.hsFetchAccepted("short"))
        assertTrue(HsControl.descEventUploaded("x.onion", "d").startsWith("HS_DESC UPLOADED"))
        val opts = HsOpts(
            services = listOf(
                HiddenServiceConfig(dataDir.resolve("hs"), listOf(HiddenServicePort(80, "127.0.0.1:8080"))),
            ),
            nonAnonymousMode = true,
            singleHopMode = false,
        )
        assertTrue(opts.validate().any { it.contains("NonAnonymous") })
        HsSys.init(TorConfig(dataDirectory = dataDir))
        assertFalse(HsSys.isStarted())
        HsMetrics.reset()
        HsMetrics.noteDescUpload()
        assertTrue(HsMetrics.exportPrometheus().contains("hs_desc_uploads"))
    }
}
