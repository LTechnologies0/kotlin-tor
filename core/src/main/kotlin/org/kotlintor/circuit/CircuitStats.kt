package org.kotlintor.circuit

import java.util.concurrent.ConcurrentLinkedQueue
import kotlin.math.ln
import kotlin.random.Random

/**
 * Circuit build-time / timeout stats (C Tor `circuitstats.c`).
 *
 * Inventory: `L1:core/or/circuitstats.c`
 *
 * Tracks recent circuit build durations and derives a timeout quantile.
 */
object CircuitStats {
    const val DEFAULT_TIMEOUT_MS: Long = 60_000
    const val DEFAULT_CLOSE_MS: Long = 60_000
    const val MAX_SAMPLES: Int = 1000
    const val NUM_XM_MODES: Int = 10

    data class BuildTimes(
        var timeoutMs: Long = DEFAULT_TIMEOUT_MS,
        var closeMs: Long = DEFAULT_CLOSE_MS,
        var numCircs: Int = 0,
        var totalClosed: Int = 0,
        var totalTimeouts: Int = 0,
        var alpha: Double = 0.0,
        var xm: Long = 0,
        var disabled: Boolean = false,
        var networkLive: Boolean = true,
        var measurementOnly: Boolean = false,
    )

    private val samples = ConcurrentLinkedQueue<Long>()
    private var state = BuildTimes()
    private var lastLiveMs: Long = System.currentTimeMillis()

    fun reset() {
        samples.clear()
        state = BuildTimes()
    }

    fun snapshot(): BuildTimes = state.copy()

    /** Record a successful circuit build duration (ms). */
    fun noteBuildTime(ms: Long) {
        if (ms < 0) return
        samples.add(ms)
        while (samples.size > MAX_SAMPLES) samples.poll()
        state = state.copy(numCircs = state.numCircs + 1)
        recompute()
    }

    fun timeoutMs(): Long = state.timeoutMs

    fun closeMs(): Long = state.closeMs

    fun sampleCount(): Int = samples.size

    private fun recompute() {
        val sorted = samples.sorted()
        if (sorted.isEmpty()) return
        // ~80th percentile like C Tor CBT quantile default
        val idx = ((sorted.size - 1) * 0.80).toInt().coerceIn(0, sorted.lastIndex)
        val q = sorted[idx].coerceAtLeast(10)
        val xm = circuitBuildTimesGetXm()
        state = state.copy(
            timeoutMs = (q * 1.5).toLong().coerceIn(10, 10 * 60_000L),
            closeMs = (q * 2.0).toLong().coerceIn(10, 10 * 60_000L),
            xm = xm,
            alpha = circuitBuildTimesInitialAlpha(),
        )
    }

    // --- C Tor circuitstats.h / circuit_build_times_* (L3) ---

    /** C Tor `circuit_build_times_add_time`. */
    fun circuitBuildTimesAddTime(ms: Long) = noteBuildTime(ms)

    /** C Tor `circuit_build_times_calculate_timeout`. */
    fun circuitBuildTimesCalculateTimeout(quantile: Double = 0.8): Long {
        val sorted = samples.sorted()
        if (sorted.isEmpty()) return state.timeoutMs
        val idx = ((sorted.size - 1) * quantile.coerceIn(0.0, 1.0)).toInt()
        return sorted[idx].coerceAtLeast(10)
    }

    /** C Tor `circuit_build_times_cdf`. */
    fun circuitBuildTimesCdf(x: Long): Double {
        if (samples.isEmpty()) return 0.0
        return samples.count { it <= x }.toDouble() / samples.size
    }

    /** C Tor `circuit_build_times_close_rate`. */
    fun circuitBuildTimesCloseRate(): Double {
        val n = state.numCircs.coerceAtLeast(1)
        return state.totalClosed.toDouble() / n
    }

    /** C Tor `circuit_build_times_count_close`. */
    fun circuitBuildTimesCountClose() {
        state = state.copy(totalClosed = state.totalClosed + 1)
    }

    /** C Tor `circuit_build_times_count_timeout`. */
    fun circuitBuildTimesCountTimeout() {
        state = state.copy(totalTimeouts = state.totalTimeouts + 1)
    }

    /** C Tor `circuit_build_times_disabled` / `circuit_build_times_disabled_`. */
    fun circuitBuildTimesDisabled(): Boolean = state.disabled

    fun circuitBuildTimesDisabledSet(disabled: Boolean) {
        state = state.copy(disabled = disabled)
    }

    /** C Tor `circuit_build_times_enough_to_compute`. */
    fun circuitBuildTimesEnoughToCompute(minSamples: Int = 100): Boolean =
        samples.size >= minSamples

    /** C Tor `circuit_build_times_free_timeouts`. */
    fun circuitBuildTimesFreeTimeouts() {
        samples.clear()
    }

    /** C Tor `circuit_build_times_generate_sample` — Pareto-ish from xm/alpha. */
    fun circuitBuildTimesGenerateSample(rng: Random = Random.Default): Long {
        val xm = circuitBuildTimesGetXm().coerceAtLeast(1)
        val a = circuitBuildTimesInitialAlpha().coerceAtLeast(0.1)
        val u = rng.nextDouble().coerceIn(1e-9, 1.0)
        return (xm / Math.pow(u, 1.0 / a)).toLong().coerceIn(1, 10 * 60_000L)
    }

    /** C Tor `circuit_build_times_get_xm`. */
    fun circuitBuildTimesGetXm(): Long {
        val sorted = samples.sorted()
        if (sorted.isEmpty()) return state.xm
        val modeBucket = sorted.size / NUM_XM_MODES.coerceAtLeast(1)
        val idx = modeBucket.coerceIn(0, sorted.lastIndex)
        return sorted[idx]
    }

    /** C Tor `circuit_build_times_handle_completed_hop`. */
    fun circuitBuildTimesHandleCompletedHop(hopBuildMs: Long) = noteBuildTime(hopBuildMs)

    /** C Tor `circuit_build_times_init`. */
    fun circuitBuildTimesInit() {
        reset()
        state = BuildTimes(
            timeoutMs = circuitBuildTimesInitialTimeout(),
            alpha = circuitBuildTimesInitialAlpha(),
        )
    }

    /** C Tor `circuit_build_times_initial_alpha`. */
    fun circuitBuildTimesInitialAlpha(): Double = if (samples.size < 2) 2.0 else {
        val xm = circuitBuildTimesGetXm().toDouble().coerceAtLeast(1.0)
        val sum = samples.sumOf { ln((it.coerceAtLeast(1)).toDouble() / xm) }
        (samples.size / sum.coerceAtLeast(1e-9)).coerceIn(0.1, 20.0)
    }

    /** C Tor `circuit_build_times_initial_timeout`. */
    fun circuitBuildTimesInitialTimeout(): Long = DEFAULT_TIMEOUT_MS

    /** C Tor `circuit_build_times_mark_circ_as_measurement_only`. */
    fun circuitBuildTimesMarkCircAsMeasurementOnly() {
        state = state.copy(measurementOnly = true)
    }

    /** C Tor `circuit_build_times_needs_circuits`. */
    fun circuitBuildTimesNeedsCircuits(): Boolean =
        !state.disabled && samples.size < MAX_SAMPLES / 2

    /** C Tor `circuit_build_times_needs_circuits_now`. */
    fun circuitBuildTimesNeedsCircuitsNow(): Boolean =
        circuitBuildTimesNeedsCircuits() && state.networkLive

    /** C Tor `circuit_build_times_network_check_changed`. */
    fun circuitBuildTimesNetworkCheckChanged(nowMs: Long = System.currentTimeMillis()): Boolean {
        val live = nowMs - lastLiveMs < 60_000
        val changed = live != state.networkLive
        state = state.copy(networkLive = live)
        return changed
    }

    /** C Tor `circuit_build_times_network_check_live`. */
    fun circuitBuildTimesNetworkCheckLive(): Boolean = state.networkLive

    /** C Tor `circuit_build_times_network_circ_success`. */
    fun circuitBuildTimesNetworkCircSuccess(nowMs: Long = System.currentTimeMillis()) {
        lastLiveMs = nowMs
        state = state.copy(networkLive = true)
    }

    /** C Tor `circuit_build_times_network_is_live`. */
    fun circuitBuildTimesNetworkIsLive(): Boolean = state.networkLive

    /** C Tor `circuit_build_times_new_consensus_params`. */
    fun circuitBuildTimesNewConsensusParams(params: Map<String, Long>) {
        val disabled = (params["cbtquantile"] ?: 80L) <= 0
        state = state.copy(disabled = disabled)
    }

    /** C Tor `circuit_build_times_parse_state` — restore from timeout/close/num. */
    fun circuitBuildTimesParseState(timeoutMs: Long, closeMs: Long, numCircs: Int) {
        state = BuildTimes(timeoutMs = timeoutMs, closeMs = closeMs, numCircs = numCircs)
    }
}
