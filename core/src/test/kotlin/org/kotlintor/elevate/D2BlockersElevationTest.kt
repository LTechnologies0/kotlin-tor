package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.config.TorrcParser
import org.kotlintor.link.ChannelScheduler
import org.kotlintor.link.SchedulerType
import org.kotlintor.circuit.CircuitPaddingMachines
import org.kotlintor.circuit.CircuitPaddingSession
import org.kotlintor.circuit.ConfluxScheduler
import org.kotlintor.circuit.ConfluxSet
import java.nio.file.Path

/**
 * Phase 2 D2 deepeners (still at most D2 while lite/not-ported):
 * dormant FSM options, KIST-Lite select, WTF-PAD middle ACK hooks, conflux set.
 */
class D2BlockersElevationTest {
    @Test
    fun `scheduler prefers kist then lite`() {
        // Full KIST is opt-in; without KOTLIN_TOR_KIST_PYTHON, skip to VANILLA.
        assertEquals(
            SchedulerType.VANILLA,
            ChannelScheduler.select(listOf(SchedulerType.KIST, SchedulerType.VANILLA)),
        )
        assertEquals(
            SchedulerType.KIST_LITE,
            ChannelScheduler.select(listOf(SchedulerType.KIST_LITE)),
        )
    }

    @Test
    fun `circpad middle ack hooks do not throw`() {
        val spec = CircuitPaddingMachines.clientHideIntro()
        val session = CircuitPaddingSession(spec, sendDrop = {})
        session.onIntroduce1Sent()
        session.onMiddleNonPaddingReceived()
        session.onMiddlePaddingReceived()
        assertTrue(session.remaining >= 0)
    }

    @Test
    fun `conflux set empty pickLeg is null`() {
        val set = ConfluxSet(ByteArray(32))
        val sched = ConfluxScheduler(set)
        assertTrue(sched.pickLeg() == null)
    }

    @Test
    fun `dormant options parse`() {
        val c = TorrcParser.parse(
            """
            DataDirectory /tmp/ktor-d2
            DormantTimeoutEnabled 1
            DormantClientTimeout 120
            Schedulers KIST,KISTLite,Vanilla
            """.trimIndent(),
            Path.of("/tmp/ktor-d2"),
        )
        assertTrue(c.runtime.dormantTimeoutEnabled)
        assertEquals(120L, c.runtime.dormantClientTimeoutSec)
        assertFalse(c.runtime.dormantOnFirstStartup)
    }
}
