package org.kotlintor.or

import org.kotlintor.config.ListenSpec

/** C Tor `channel_listener_t` — OR listener bookkeeping. */
data class ChannelListener(
    val listen: ListenSpec,
    var accepted: Long = 0,
)
