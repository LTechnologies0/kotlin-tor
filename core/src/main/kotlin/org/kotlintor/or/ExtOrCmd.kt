package org.kotlintor.or

/** C Tor `ext_or_cmd_t`. */
data class ExtOrCmd(
    val command: String,
    val body: String = "",
)
