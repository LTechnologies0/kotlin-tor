package org.kotlintor.cell

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

/** Mirrors C Tor encode_v1_cell / decode_v1_cell (relay_msg.c). */
class RelayCellV1Test {
    @Test
    fun `EXTEND2 V1 has no stream id — body at offset 19`() {
        val body = ByteArray(40) { it.toByte() }
        val cell = RelayCell.build(RelayCommand.EXTEND2, 0, body)
        val packed = cell.toPayloadV1(pad = false)
        assertEquals(509, packed.size)
        // Tag area zeros before CGO originate.
        assertArrayEquals(ByteArray(16), packed.copyOfRange(0, 16))
        assertEquals(RelayCommand.EXTEND2.id, packed[16].toInt() and 0xff)
        assertEquals(40, ((packed[17].toInt() and 0xff) shl 8) or (packed[18].toInt() and 0xff))
        assertArrayEquals(body, packed.copyOfRange(19, 59))

        val parsed = RelayCell.parseV1(packed)
        assertEquals(RelayCommand.EXTEND2, parsed.command)
        assertEquals(0, parsed.streamId)
        assertArrayEquals(body, parsed.data)
    }

    @Test
    fun `DATA V1 carries stream id — body at offset 21`() {
        val body = "hello-v1".toByteArray()
        val packed = RelayCell.build(RelayCommand.DATA, 7, body).toPayloadV1(pad = false)
        assertEquals(7, ((packed[19].toInt() and 0xff) shl 8) or (packed[20].toInt() and 0xff))
        assertArrayEquals(body, packed.copyOfRange(21, 21 + body.size))

        val parsed = RelayCell.parseV1(packed)
        assertEquals(RelayCommand.DATA, parsed.command)
        assertEquals(7, parsed.streamId)
        assertArrayEquals(body, parsed.data)
    }

    @Test
    fun `V1 rejects stream id on EXTEND2`() {
        assertThrows(IllegalArgumentException::class.java) {
            RelayCell.build(RelayCommand.EXTEND2, 1, ByteArray(8)).toPayloadV1(pad = false)
        }
    }

    @Test
    fun `V1 rejects zero stream on DATA`() {
        assertThrows(IllegalArgumentException::class.java) {
            RelayCell.build(RelayCommand.DATA, 0, ByteArray(8)).toPayloadV1(pad = false)
        }
    }
}
