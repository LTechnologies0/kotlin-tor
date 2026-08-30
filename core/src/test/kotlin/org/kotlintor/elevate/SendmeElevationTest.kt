package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.kotlintor.circuit.Sendme

/**
 * Elevates `L1:core/or/sendme.c` D2→D3.
 *
 * Evidence: build_cell_payload_v1, sendme_is_valid, version consensus,
 * circuit/stream window increments vs sendme.c.
 */
class SendmeElevationTest {
    @BeforeEach
    fun reset() {
        Sendme.emitMinVersion = 1
        Sendme.acceptMinVersion = 0
    }

    @Test
    fun `v1 payload and version handling`() {
        val tag = ByteArray(20) { it.toByte() }
        val payload = Sendme.buildCellPayloadV1(tag)
        assertEquals(23, payload.size)
        assertEquals(1, payload[0].toInt() and 0xff)
        assertTrue(Sendme.cellVersionCanBeHandled(0))
        assertTrue(Sendme.cellVersionCanBeHandled(1))
        assertFalse(Sendme.cellVersionCanBeHandled(2))
        Sendme.acceptMinVersion = 1
        assertFalse(Sendme.cellVersionCanBeHandled(0))
        Sendme.newConsensusParams(mapOf("sendme_emit_min_version" to 0L))
        assertEquals(0, Sendme.emitMinVersionResolved())
        assertTrue(Sendme.emitPayload(tag).isEmpty())
    }

    @Test
    fun `digest queue validates sendme`() {
        val q = Sendme.DigestQueue()
        val tag = ByteArray(20) { 7 }
        q.record(tag)
        val good = Sendme.buildCellPayloadV1(tag)
        assertTrue(Sendme.isValid(q, good))
        assertEquals(0, q.size())
        q.record(tag)
        val bad = Sendme.buildCellPayloadV1(ByteArray(20) { 9 })
        assertFalse(Sendme.isValid(q, bad))
        assertTrue(Sendme.isValid(q, ByteArray(0))) // v0 empty
    }

    @Test
    fun `circuit and stream windows`() {
        // After receiving the cell that lands deliver_window on a multiple of CIRCWINDOW_INCREMENT.
        val (_, cell) = Sendme.circuitDataReceived(101, ByteArray(20) { 1 }, increment = 100)
        assertTrue(cell != null && cell!!.isNotEmpty())
        assertEquals(999, Sendme.noteCircuitDataPackaged(1000))
        assertEquals(1100, Sendme.processCircuitLevel(1000))
        val (dw, due) = Sendme.streamDataReceived(51)
        assertEquals(50, dw)
        assertTrue(due)
        assertEquals(550, Sendme.processStreamLevel(500))
    }
}
