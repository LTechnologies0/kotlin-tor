package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.kotlintor.circuit.RelayCrypto
import org.kotlintor.config.ListenSpec
import org.kotlintor.config.TorConfig
import org.kotlintor.crypto.OnionFast
import org.kotlintor.hs.HsCache
import org.kotlintor.hs.HsCommon
import org.kotlintor.path.CircPathBias
import org.kotlintor.path.PathState
import org.kotlintor.relay.DosSys
import org.kotlintor.relay.OrSys
import org.kotlintor.relay.RouterMode
import java.nio.file.Files

/**
 * Elevates:
 * - L1:core/crypto/onion_fast.c
 * - L1:core/crypto/relay_crypto.c
 * - L1:feature/hs/hs_cache.c
 * - L1:feature/hs/hs_common.c
 * - L1:core/or/dos_sys.c
 * - L1:core/or/or_sys.c
 * - L1:feature/client/circpathbias.c
 */
class OnionFastRelayDosHsElevationTest {
    @BeforeEach
    fun reset() {
        DosSys.shutdown()
        OrSys.shutdown()
        RouterMode.setServerAdvertised(false)
    }

    @Test
    fun `onion_fast client server roundtrip`() {
        val (st, x) = OnionFast.clientBegin()
        val (hs, server) = OnionFast.serverRespond(x)
        val client = OnionFast.clientFinish(st, hs)
        assertArrayEquals(server.kh, client.kh)
        assertEquals(20, client.forwardDigest.size)
        assertEquals(16, client.forwardKey.size)
    }

    @Test
    fun `relay_crypto tor1 from create_fast`() {
        val (st, x) = OnionFast.clientBegin()
        val (hs, _) = OnionFast.serverRespond(x)
        val keys = OnionFast.clientFinish(st, hs)
        val hop = RelayCrypto.newTor1FromCreateFast(keys)
        assertEquals(509, hop.originateOutbound(ByteArray(509)).size)
        assertTrue(hop.inboundDigest().isNotEmpty())
    }

    @Test
    fun `hs_cache store lookup clean oom`() {
        val c = HsCache(maxDescriptorBytes = 1000, maxEntries = 10, maxLifetimeSec = 3600)
        assertTrue(c.storeAsDir("AABB", "desc-body"))
        assertEquals("desc-body", c.lookupAsDir("aabb"))
        assertEquals(1, c.dirSize())
        c.noteIntroState("svc1", "intro1", timedOut = true)
        assertEquals(1, c.findIntroState("svc1", "intro1")?.unreachableCount)
        assertTrue(c.handleOom(1) >= 1)
        assertEquals(0, c.dirSize())
    }

    @Test
    fun `hs_common period helpers`() {
        assertTrue(HsCommon.timePeriodNum() > 0)
        assertTrue(HsCommon.validatePeriodIndex(1))
        assertFalse(HsCommon.validatePeriodIndex(0))
        assertEquals(1440 * 60L, HsCommon.timePeriodLengthSec())
        assertTrue(HsCommon.hsdirIndexHint("AB", 1, 0).contains("|1|0"))
    }

    @Test
    fun `dos_sys initialize shutdown`() {
        assertEquals(0, DosSys.initialize())
        assertTrue(DosSys.isInitialized())
        assertTrue(DosSys.allowConnection("203.0.113.9"))
        DosSys.shutdown()
        assertFalse(DosSys.isInitialized())
        assertTrue(DosSys.allowConnection("203.0.113.9")) // passthrough when down
    }

    @Test
    fun `or_sys initialize`() {
        val cfg = TorConfig(
            dataDirectory = Files.createTempDirectory("ktor-or-sys"),
            clientOnly = false,
            orPort = ListenSpec("127.0.0.1", 9001),
        )
        assertEquals(0, OrSys.initialize(cfg))
        assertTrue(OrSys.isInitialized())
        assertTrue(OrSys.shouldRunRelay(cfg))
        OrSys.shutdown()
        assertFalse(OrSys.isInitialized())
    }

    @Test
    fun `circpathbias build success path`() {
        val t = CircPathBias.newTracker()
        t.markBuildAttempted(1, "guardA")
        t.markBuildSucceeded(1, "guardA")
        assertEquals(PathState.BUILD_SUCCEEDED, t.state(1))
        val c = t.counters("guardA")
        assertTrue(c.circAttempted >= 1)
        assertTrue(c.circSucceeded >= 1)
    }
}
