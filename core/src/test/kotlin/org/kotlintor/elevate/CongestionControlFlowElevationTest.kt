package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.kotlintor.circuit.CongestionControlFlow

/**
 * Elevates `L1:core/or/congestion_control_flow.c` D2→D3.
 *
 * Evidence: flow_control_new_consensus_params, decide_xoff grace, encode xon/xoff,
 * decide_xon resume vs congestion_control_flow.c.
 */
class CongestionControlFlowElevationTest {
    @BeforeEach
    fun reset() {
        CongestionControlFlow.newConsensusParams(emptyMap())
        CongestionControlFlow.resetStats()
    }

    @Test
    fun `consensus params defaults and clamp`() {
        val d = CongestionControlFlow.params
        assertEquals(500 * CongestionControlFlow.RELAY_PAYLOAD_SIZE_MIN, d.xoffClient)
        assertEquals(25, d.xonChangePct)
        CongestionControlFlow.newConsensusParams(mapOf("cc_xoff_client" to 2L, "cc_xon_change_pct" to 50L))
        assertEquals(2 * CongestionControlFlow.RELAY_PAYLOAD_SIZE_MIN, CongestionControlFlow.params.xoffClient)
        assertEquals(50, CongestionControlFlow.params.xonChangePct)
    }

    @Test
    fun `xoff after grace period then xon when drained`() {
        val s = CongestionControlFlow.EdgeState(CongestionControlFlow.EdgeKind.CLIENT_OR_HS)
        s.outbufLen = CongestionControlFlow.params.xoffClient + 1
        val t0 = 1_000_000L
        assertEquals(0, CongestionControlFlow.decideXoff(s, nowUsec = t0))
        assertNull(s.pendingXoff)
        assertTrue(s.xoffGraceStartUsec == t0)
        assertEquals(0, CongestionControlFlow.decideXoff(s, nowUsec = t0 + CongestionControlFlow.XOFF_GRACE_PERIOD_USEC + 1))
        assertNotNull(s.pendingXoff)
        assertTrue(s.xoffSent)
        assertEquals(1, CongestionControlFlow.numXoffSent)
        assertEquals(0, CongestionControlFlow.parseXoff(s.pendingXoff!!))

        s.outbufLen = 0
        s.pendingXoff = null
        CongestionControlFlow.decideXon(s, nWritten = 0, nowUsec = t0 + 10_000)
        assertNotNull(s.pendingXon)
        assertEquals(false, s.xoffSent)
        assertEquals(1, CongestionControlFlow.numXonSent)
        assertEquals(0, CongestionControlFlow.parseXon(s.pendingXon!!))
    }

    @Test
    fun `xon xoff cell codecs`() {
        val xoff = CongestionControlFlow.encodeXoff()
        assertEquals(1, xoff.size)
        val xon = CongestionControlFlow.encodeXon(12345)
        assertEquals(5, xon.size)
        assertEquals(12345, CongestionControlFlow.parseXon(xon))
    }
}
