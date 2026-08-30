package org.kotlintor.or

/** C Tor `destroy_cell_t`. */
data class DestroyCell(
    val circId: Long,
    val reason: Int = 0,
)
