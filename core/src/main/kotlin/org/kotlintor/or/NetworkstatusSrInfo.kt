package org.kotlintor.or

import org.kotlintor.dir.SharedRandom

/** C Tor `networkstatus_sr_info_t`. */
data class NetworkstatusSrInfo(
    val current: SharedRandom.Srv? = null,
    val previous: SharedRandom.Srv? = null,
)
