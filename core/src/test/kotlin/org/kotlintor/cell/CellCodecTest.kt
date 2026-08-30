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
    fun `rejects oversize variable cell before alloc`() {
        // circ_id(4) + VPADDING(128) + len=40000 (> MAX)
        val header = byteArrayOf(0, 0, 0, 0, 128.toByte(), 0x9c.toByte(), 0x40.toByte())
        val ex = org.junit.jupiter.api.Assertions.assertThrows(java.io.IOException::class.java) {
            CellCodec.read(ByteArrayInputStream(header))
        }
        assertTrue(ex.message!!.contains("exceeds max"))
    }

    @Test
    fun `skips unknown fixed command and reads next`() {
        val junkCmd = 50 // unknown, <128 → fixed
        val junk = ByteArray(4 + 1 + Cell.FIXED_PAYLOAD_LEN) { 0 }
        junk[4] = junkCmd.toByte()
        val good = Cell(1, CellCommand.PADDING, ByteArray(Cell.FIXED_PAYLOAD_LEN))
        val stream = ByteArrayInputStream(junk + CellCodec.encode(good))
        val decoded = CellCodec.read(stream)
        assertEquals(CellCommand.PADDING, decoded.command)
        assertEquals(1L, decoded.circId)
    }
}
