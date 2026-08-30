package org.kotlintor.or

/** C Tor `socks_request_t`. */
data class SocksRequest(
    val command: Int,
    val host: String,
    val port: Int,
    val username: String? = null,
    val password: String? = null,
)
