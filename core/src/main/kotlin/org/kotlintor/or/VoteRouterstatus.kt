package org.kotlintor.or

import org.kotlintor.dir.RouterStatus

/** C Tor `vote_routerstatus_t`. */
data class VoteRouterstatus(
    val status: RouterStatus,
    val flags: Set<String> = emptySet(),
    val measuredBw: Int? = null,
)
