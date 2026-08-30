package org.kotlintor.or

/** C Tor `conflux_leg_t`. */
data class ConfluxLeg(
    val circId: Long,
    var lastSeqSent: Long = 0,
    var lastSeqRecv: Long = 0,
)
