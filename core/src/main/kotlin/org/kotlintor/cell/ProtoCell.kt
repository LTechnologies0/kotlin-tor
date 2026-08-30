package org.kotlintor.cell

import java.io.InputStream
import java.io.OutputStream

/**
 * Cell packing/unpacking (C Tor `proto_cell.c`).
 *
 * Inventory: `L1:core/proto/proto_cell.c`
 *
 * Naming-aligned entry over [CellCodec].
 */
object ProtoCell {
    const val FIXED_PAYLOAD_LEN: Int = Cell.FIXED_PAYLOAD_LEN

    fun encode(cell: Cell, circIdLen: Int = 4): ByteArray = CellCodec.encode(cell, circIdLen)

    fun write(out: OutputStream, cell: Cell, circIdLen: Int = 4) =
        CellCodec.write(out, cell, circIdLen)

    fun read(input: InputStream, circIdLen: Int = 4): Cell = CellCodec.read(input, circIdLen)

    fun circIdLenForLinkProtocol(linkProto: Int): Int = if (linkProto >= 4) 4 else 2
}
