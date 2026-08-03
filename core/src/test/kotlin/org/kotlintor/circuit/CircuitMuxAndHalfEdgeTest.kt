package org.kotlintor.circuit

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CircuitMuxAndHalfEdgeTest {
    @Test
    fun `ewma prefers quieter circuit`() {
        val mux = CircuitMux(EwmaCircuitMuxPolicy(halfLifeSec = 30.0))
        // Keep both active after xmit (queue -= nCells).
        mux.attach(1, initialCells = 100)
        mux.attach(2, initialCells = 100)
        mux.notifyXmit(1, 50)
        mux.notifyXmit(2, 1)
        // Circuit 2 quieter EWMA → pick 2
        assertEquals(2L, mux.pickActive())
    }

    @Test
    fun `destroy queue preferred`() {
        val mux = CircuitMux()
        mux.attach(9, 1)
        mux.queueDestroy(42)
        assertEquals(42L, mux.pickActive())
    }

    @Test
    fun `cell queue enqueue dequeue`() {
        val mux = CircuitMux()
        mux.attach(7)
        assertTrue(mux.enqueue(7, byteArrayOf(1, 2, 3)))
        assertEquals(1, mux.circuitQueueSize(7))
        assertTrue(mux.isActive(7))
        assertArrayEquals(byteArrayOf(1, 2, 3), mux.dequeue(7))
        assertEquals(0, mux.circuitQueueSize(7))
    }

    @Test
    fun `ewma from consensus CircuitPriorityHalflifeMsec`() {
        val p = EwmaCircuitMuxPolicy.fromConsensus(mapOf("CircuitPriorityHalflifeMsec" to 45_000L))
        assertEquals(45.0, p.halfLifeSec, 0.001)
    }

    @Test
    fun `half edge accepts depleting windows`() {
        val set = HalfEdgeSet()
        set.add(HalfEdge(streamId = 7, sendmesPending = 1, dataPending = 2))
        assertTrue(set.acceptInbound(7, isSendme = false, isData = true))
        assertTrue(set.acceptInbound(7, isSendme = false, isData = true))
        assertTrue(set.acceptInbound(7, isSendme = true, isData = false))
        assertFalse(set.contains(7))
    }
}
