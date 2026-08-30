package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.cell.CircuitPurpose
import org.kotlintor.circuit.CircuitList
import org.kotlintor.relay.BwHist
import org.kotlintor.status.HeartbeatStatus

/**
 * Elevates:
 * - L1:core/or/circuitlist.c (D1→D2)
 * - L1:core/or/status.c (D1→D2)
 * - L2:feature/stats/bw_array_t (D0→D2)
 */
class CircuitListStatusBwArrayElevationTest {
    @Test
    fun `circuitlist purpose dirty counts`() {
        CircuitList.clear()
        CircuitList.registerOrigin(1, CircuitPurpose.GENERAL)
        CircuitList.registerOrigin(2, CircuitPurpose.HS_CLIENT_INTRO)
        CircuitList.registerOr(3, isExit = true)
        CircuitList.markDirty(1)
        assertEquals(1, CircuitList.byPurpose(CircuitPurpose.HS_CLIENT_INTRO).size)
        assertEquals(1, CircuitList.dirtyCircuits().size)
        assertEquals(2, CircuitList.countOrigins())
        assertEquals(1, CircuitList.countOrs())
        CircuitList.clear()
    }

    @Test
    fun `status heartbeat counters`() {
        HeartbeatStatus.resetClock(1_000)
        val line = HeartbeatStatus.format(10, 20, true, circuitsOpen = 2, orConns = 1, nowMs = 6_000)
        assertTrue(line.contains("uptime=0:00 hours"), line)
        assertTrue(line.contains("circuits=2"), line)
        assertEquals(1, HeartbeatStatus.heartbeatCount())
        assertEquals(0, HeartbeatStatus.lastHeartbeatAgeMs(6_000))
    }

    @Test
    fun `bw_array slot mirror`() {
        val slot = BwHist.Slot(read = 5, written = 7)
        val arr = slot.toBwArray()
        assertEquals(5, arr.read)
        assertEquals(7, arr.written)
    }
}
