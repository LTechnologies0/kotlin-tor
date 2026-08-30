package org.kotlintor.or

/** C Tor `control_cmd_args_t`. */
data class ControlCmdArgs(
    val keywords: Map<String, String> = emptyMap(),
    val args: List<String> = emptyList(),
    val rawBody: String? = null,
)
