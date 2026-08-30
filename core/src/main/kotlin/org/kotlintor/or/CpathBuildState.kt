package org.kotlintor.or

/** C Tor `cpath_build_state_t`. */
data class CpathBuildState(
    val desiredPathLen: Int = 3,
    val exitFingerprintHex: String? = null,
    val isInternal: Boolean = false,
)
