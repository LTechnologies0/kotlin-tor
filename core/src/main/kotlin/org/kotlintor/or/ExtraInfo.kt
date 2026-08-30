package org.kotlintor.or

/** C Tor `extrainfo_t`. */
data class ExtraInfo(
    val nickname: String,
    val identityHex: String,
    val body: String,
)
