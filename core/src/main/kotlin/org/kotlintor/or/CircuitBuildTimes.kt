package org.kotlintor.or

/** C Tor `circuit_build_times_t`. */
data class CircuitBuildTimes(
    var timeoutMs: Long = 60_000,
    var closeMs: Long = 60_000,
    var numCircs: Int = 0,
)
