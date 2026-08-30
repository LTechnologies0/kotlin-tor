package org.kotlintor.or

/** C Tor `vegas_params_t`. */
data class VegasParams(
    val alpha: Int = 3 * 31,
    val beta: Int = 4 * 31,
    val delta: Int = 5 * 31,
    val gamma: Int = 3 * 31,
    val ssCap: Int = 5_000,
)
