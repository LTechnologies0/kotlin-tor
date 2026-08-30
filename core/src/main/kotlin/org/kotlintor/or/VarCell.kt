package org.kotlintor.or

import org.kotlintor.cell.Cell

/** C Tor `var_cell_t` — variable-length cell wrapper. */
data class VarCell(
    val circId: Long,
    val command: Int,
    val payload: ByteArray,
) {
    fun toCell(cmd: org.kotlintor.cell.CellCommand): Cell = Cell(circId, cmd, payload)
    override fun equals(other: Any?): Boolean =
        other is VarCell && circId == other.circId && command == other.command &&
            payload.contentEquals(other.payload)
    override fun hashCode(): Int = circId.hashCode() xor command xor payload.contentHashCode()
}
