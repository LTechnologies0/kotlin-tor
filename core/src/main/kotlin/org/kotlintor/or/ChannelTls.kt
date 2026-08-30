package org.kotlintor.or

/** C Tor `channel_tls_t` — TLS OR channel tag. */
data class ChannelTls(
    val peerHost: String,
    val peerPort: Int,
    var linkProtocol: Int = 4,
)
