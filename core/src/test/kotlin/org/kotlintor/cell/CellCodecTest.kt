package org.kotlintor.cell

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class CellCodecTest {
    @Test
    fun `round trip fixed cell`() {
        val payload = ByteArray(Cell.FIXED_PAYLOAD_LEN) { it.toByte() }
        val cell = Cell(0x80000001L, CellCommand.CREATE2, payload)
        val encoded = CellCodec.encode(cell)
        assertEquals(4 + 1 + 509, encoded.size)
        val decoded = CellCodec.read(ByteArrayInputStream(encoded))
        assertEquals(cell.circId, decoded.circId)
        assertEquals(cell.command, decoded.command)
        assertTrue(cell.payload.contentEquals(decoded.payload))
    }

    @Test
    fun `round trip variable VERSIONS cell`() {
        val cell = Cell(0, CellCommand.VERSIONS, byteArrayOf(0, 4, 0, 5))
        val baos = ByteArrayOutputStream()
        CellCodec.write(baos, cell)
        val decoded = CellCodec.read(ByteArrayInputStream(baos.toByteArray()))
        assertEquals(CellCommand.VERSIONS, decoded.command)
        assertEquals(4, decoded.payload.size)
    }

    @Test
    fun `pre-negotiation VERSIONS uses 2-byte circ id`() {
        val cell = Cell(0, CellCommand.VERSIONS, byteArrayOf(0, 3, 0, 4, 0, 5))
        val encoded = CellCodec.encode(cell, circIdLen = 2)
        assertEquals(2 + 1 + 2 + 6, encoded.size)
        val decoded = CellCodec.read(ByteArrayInputStream(encoded), circIdLen = 2)
        assertEquals(CellCommand.VERSIONS, decoded.command)
        assertEquals(6, decoded.payload.size)
    }

    @Test
    fun `relay cell payload layout`() {
        val relay = RelayCell.build(RelayCommand.BEGIN, 7, "example.com:80\u0000".toByteArray())
        val payload = relay.toPayload()
        assertEquals(509, payload.size)
        val parsed = RelayCell.parse(payload)
        assertEquals(RelayCommand.BEGIN, parsed.command)
        assertEquals(7, parsed.streamId)
        assertEquals(relay.length, parsed.length)
    }
}
