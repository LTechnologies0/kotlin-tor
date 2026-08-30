package org.kotlintor.dir

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Vote flag assignment heuristics (C Tor `voteflags.c`).
 *
 * Inventory: `L1:feature/dirauth/voteflags.c`
 *
 * Produces the flag set an authority would advertise for a relay given
 * measured bandwidth, uptime, and reachability.
 */
object VoteFlags {
    data class Input(
        val isAuthority: Boolean = false,
        val isRunning: Boolean = true,
        val isValid: Boolean = true,
        val isExit: Boolean = false,
        val isBadExit: Boolean = false,
        val bandwidthKb: Int = 0,
        val weightedBwKb: Int = 0,
        val uptimeSec: Long = 0,
        val reachable: Boolean = true,
        val supportsHsDir: Boolean = false,
        val hasEdConsensus: Boolean = true,
        val stableUptimeSec: Long = 7 * 24 * 3600,
        val guardBwThresholdKb: Int = 2_000,
        val fastBwThresholdKb: Int = 100,
    )

    fun assign(input: Input): Set<String> {
        val flags = LinkedHashSet<String>()
        if (input.isAuthority) flags += "Authority"
        if (input.isValid) flags += "Valid"
        if (input.isRunning && input.reachable) flags += "Running"
        if (input.isExit) flags += "Exit"
        if (input.isBadExit) flags += "BadExit"
        if (input.bandwidthKb >= input.fastBwThresholdKb) flags += "Fast"
        if (input.uptimeSec >= input.stableUptimeSec) flags += "Stable"
        if ("Fast" in flags && "Stable" in flags &&
            input.weightedBwKb >= input.guardBwThresholdKb
        ) {
            flags += "Guard"
        }
        if (input.supportsHsDir && "Fast" in flags) flags += "HSDir"
        if (!input.hasEdConsensus) flags += "NoEdConsensus"
        flags += "V2Dir"
        return flags
    }

    data class RouterStatusLite(
        val identityHex: String,
        val nickname: String,
        val flags: Set<String>,
        val bandwidthKb: Int,
    )

    /**
     * C Tor `dirauth_set_routerstatus_from_routerinfo` — build status flags from input.
     */
    fun dirauthSetRouterstatusFromRouterinfo(
        identityHex: String,
        nickname: String,
        input: Input,
    ): RouterStatusLite =
        RouterStatusLite(identityHex, nickname, assign(input), input.bandwidthKb)

    data class Thresholds(
        val fastSpeedKb: Int = 100,
        val guardBwIncExitsKb: Int = 2000,
        val stableUptimeSec: Long = 7 * 24 * 3600,
    )

    /** C Tor `dirserv_compute_performance_thresholds` — simplified fixed thresholds. */
    fun dirservComputePerformanceThresholds(omitAsSybil: Set<String> = emptySet()): Thresholds {
        // omitAsSybil reserved for future sybil filtering
        return Thresholds()
    }

    /** C Tor `dirserv_compute_bridge_flag_thresholds`. */
    fun dirservComputeBridgeFlagThresholds(): Thresholds =
        Thresholds(fastSpeedKb = 50, guardBwIncExitsKb = 500)

    /** C Tor `dirserv_get_flag_thresholds_line`. */
    fun dirservGetFlagThresholdsLine(t: Thresholds = dirservComputePerformanceThresholds()): String =
        "stable-uptime=${t.stableUptimeSec} stable-mtbf=0 fast-speed=${t.fastSpeedKb} " +
            "guard-wfu=0 guard-tk=0 guard-bw-inc-exits=${t.guardBwIncExitsKb} " +
            "guard-bw-exc-exits=0 enough-mtbf=0 ignoring-advertised-bws=0"

    private val runningById = ConcurrentHashMap<String, Boolean>()
    private val bridgesRunning = AtomicBoolean(false)

    /** C Tor `dirserv_set_router_is_running`. */
    fun dirservSetRouterIsRunning(identityHex: String, running: Boolean) {
        runningById[identityHex.lowercase()] = running
    }

    fun isRouterRunning(identityHex: String): Boolean =
        runningById[identityHex.lowercase()] ?: false

    /** C Tor `dirserv_set_bridges_running`. */
    fun dirservSetBridgesRunning(running: Boolean) {
        bridgesRunning.set(running)
    }

    fun bridgesAreRunning(): Boolean = bridgesRunning.get()

    /**
     * C Tor `dirserv_set_routerstatus_testing` — apply TestingTorNetwork-style flags.
     */
    fun dirservSetRouterstatusTesting(identityHex: String, nickname: String): RouterStatusLite {
        val input = Input(
            isRunning = true,
            isValid = true,
            bandwidthKb = 10_000,
            weightedBwKb = 10_000,
            uptimeSec = 30L * 24 * 3600,
            reachable = true,
            supportsHsDir = true,
        )
        return dirauthSetRouterstatusFromRouterinfo(identityHex, nickname, input)
    }

    /**
     * C Tor `running_long_enough_to_decide_unreachable` —
     * true when uptime exceeds one reachability cycle.
     */
    fun runningLongEnoughToDecideUnreachable(
        uptimeSec: Long,
        cycleSec: Long = ReachabilityTracker.REACHABILITY_TEST_CYCLE_PERIOD_SEC,
    ): Boolean = uptimeSec >= cycleSec
}
