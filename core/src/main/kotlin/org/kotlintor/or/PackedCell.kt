package org.kotlintor.or

/** C Tor `packed_cell_t` — queued encoded cell bytes. */
data class PackedCell(
    val body: ByteArray,
    val insertedMs: Long = System.currentTimeMillis(),
) {
    override fun equals(other: Any?): Boolean =
        other is PackedCell && body.contentEquals(other.body)
    override fun hashCode(): Int = body.contentHashCode()
}
