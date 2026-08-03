package org.kotlintor.config

/**
 * Statistics feature flags (C Tor `*Statistics` options).
 * When a flag is false, corresponding collectors no-op / omit from heartbeats.
 */
data class StatsOptions(
    val cellStatistics: Boolean = false,
    val paddingStatistics: Boolean = false,
    val dirReqStatistics: Boolean = false,
    val entryStatistics: Boolean = false,
    val exitPortStatistics: Boolean = false,
    val connDirectionStatistics: Boolean = false,
    val hiddenServiceStatistics: Boolean = false,
    val extraInfoStatistics: Boolean = true,
    val mainloopStats: Boolean = false,
    val overloadStatistics: Boolean = false,
) {
    companion object {
        val DEFAULT = StatsOptions()
    }
}
