package org.kotlintor.path

import java.util.concurrent.ConcurrentHashMap

/**
 * Path bias state machine (C Tor `path_state_t` / `circpathbias.c`).
 *
 * Tracks build/use success rates per guard to detect tagging. Default mode is
 * notice-only (matches C Tor warning-only deployment).
 */
enum class PathState {
    NEW_CIRC,
    BUILD_ATTEMPTED,
    BUILD_SUCCEEDED,
    USE_ATTEMPTED,
    USE_SUCCEEDED,
    USE_FAILED,
    ALREADY_COUNTED,
}

data class PathBiasCounters(
    var circAttempted: Int = 0,
    var circSucceeded: Int = 0,
    var useAttempted: Int = 0,
    var useSucceeded: Int = 0,
    var useFailed: Int = 0,
)

class PathBiasTracker(
    private val noticeRate: Double = 0.70,
    private val warnRate: Double = 0.50,
    private val extremeRate: Double = 0.30,
    private val minCircs: Int = 100,
    private val useThreshold: Int = 20,
    private val noticeUseRate: Double = 0.80,
    private val extremeUseRate: Double = 0.60,
    private val useRate: Double = 0.60,
    private val scaleThreshold: Int = 300,
    private val scaleUseThreshold: Int = 100,
    /** When true, extreme assessment disables the guard (C Tor PathBiasDropGuards). */
    var dropGuards: Boolean = false,
    /** Invoked when a guard is disabled (wire to [EntryGuardFsm.disableForPathBias]). */
    var onGuardDropped: ((String) -> Unit)? = null,
) {
    constructor(opts: org.kotlintor.config.PathBiasOptions) : this(
        noticeRate = opts.noticeRate,
        warnRate = opts.warnRate,
        extremeRate = opts.extremeRate,
        minCircs = opts.circThreshold,
        useThreshold = opts.useThreshold,
        noticeUseRate = opts.noticeUseRate,
        extremeUseRate = opts.extremeUseRate,
        useRate = opts.useRate,
        scaleThreshold = opts.scaleThreshold,
        scaleUseThreshold = opts.scaleUseThreshold,
        dropGuards = opts.dropGuards,
    )
    private val byGuard = ConcurrentHashMap<String, PathBiasCounters>()
    private val circState = ConcurrentHashMap<Long, PathState>()
    private val disabledGuards = ConcurrentHashMap.newKeySet<String>()

    fun counters(guardFp: String): PathBiasCounters =
        byGuard.getOrPut(guardFp.lowercase()) { PathBiasCounters() }

    fun state(circId: Long): PathState = circState[circId] ?: PathState.NEW_CIRC

    fun isGuardDisabled(guardFp: String): Boolean =
        disabledGuards.contains(guardFp.lowercase())

    fun disabledGuards(): Set<String> = disabledGuards.toSet()

    fun enableGuard(guardFp: String) {
        disabledGuards.remove(guardFp.lowercase())
    }

    fun markBuildAttempted(circId: Long, guardFp: String) {
        val cur = state(circId)
        if (cur.ordinal > PathState.BUILD_ATTEMPTED.ordinal) return
        circState[circId] = PathState.BUILD_ATTEMPTED
        counters(guardFp).circAttempted++
    }

    fun markBuildSucceeded(circId: Long, guardFp: String) {
        if (state(circId).ordinal > PathState.BUILD_SUCCEEDED.ordinal) return
        circState[circId] = PathState.BUILD_SUCCEEDED
        counters(guardFp).circSucceeded++
    }

    fun markUseAttempted(circId: Long, guardFp: String) {
        val cur = state(circId)
        if (cur.ordinal < PathState.BUILD_SUCCEEDED.ordinal) return
        if (cur.ordinal > PathState.USE_ATTEMPTED.ordinal && cur != PathState.USE_ATTEMPTED) return
        circState[circId] = PathState.USE_ATTEMPTED
        counters(guardFp).useAttempted++
    }

    fun markUseSucceeded(circId: Long, guardFp: String) {
        if (state(circId) != PathState.USE_ATTEMPTED && state(circId) != PathState.USE_SUCCEEDED) return
        circState[circId] = PathState.USE_SUCCEEDED
        counters(guardFp).useSucceeded++
    }

    fun markUseFailed(circId: Long, guardFp: String) {
        circState[circId] = PathState.USE_FAILED
        counters(guardFp).useFailed++
        maybeDrop(guardFp)
    }

    fun markUseRollback(circId: Long) {
        if (state(circId) == PathState.USE_SUCCEEDED) {
            circState[circId] = PathState.USE_ATTEMPTED
        }
    }

    enum class Level { OK, NOTICE, WARN, EXTREME }

    fun assess(guardFp: String): Level {
        val c = counters(guardFp)
        if (c.circAttempted < minCircs) return Level.OK
        maybeScale(c)
        val rate = if (c.circAttempted == 0) 1.0 else c.circSucceeded.toDouble() / c.circAttempted
        val circLevel = when {
            rate < extremeRate -> Level.EXTREME
            rate < warnRate -> Level.WARN
            rate < noticeRate -> Level.NOTICE
            else -> Level.OK
        }
        val useLevel = assessUse(c)
        return maxOf(circLevel, useLevel).also { level ->
            if (level == Level.EXTREME) maybeDrop(guardFp)
        }
    }

    private fun assessUse(c: PathBiasCounters): Level {
        if (c.useAttempted < useThreshold) return Level.OK
        val rate = if (c.useAttempted == 0) 1.0 else c.useSucceeded.toDouble() / c.useAttempted
        return when {
            rate < extremeUseRate -> Level.EXTREME
            rate < useRate -> Level.WARN
            rate < noticeUseRate -> Level.NOTICE
            else -> Level.OK
        }
    }

    /** Scale counters down when thresholds exceeded (C Tor pathbias_scale_close_rates). */
    private fun maybeScale(c: PathBiasCounters) {
        if (c.circAttempted >= scaleThreshold && scaleThreshold > 0) {
            c.circAttempted = (c.circAttempted + 1) / 2
            c.circSucceeded = (c.circSucceeded + 1) / 2
        }
        if (c.useAttempted >= scaleUseThreshold && scaleUseThreshold > 0) {
            c.useAttempted = (c.useAttempted + 1) / 2
            c.useSucceeded = (c.useSucceeded + 1) / 2
            c.useFailed = (c.useFailed + 1) / 2
        }
    }

    private fun maybeDrop(guardFp: String) {
        if (!dropGuards) return
        if (assessWithoutDrop(guardFp) == Level.EXTREME) {
            val key = guardFp.lowercase()
            if (disabledGuards.add(key)) {
                onGuardDropped?.invoke(key)
            }
        }
    }

    private fun assessWithoutDrop(guardFp: String): Level {
        val c = counters(guardFp)
        if (c.circAttempted < minCircs) return Level.OK
        maybeScale(c)
        val rate = if (c.circAttempted == 0) 1.0 else c.circSucceeded.toDouble() / c.circAttempted
        val circLevel = when {
            rate < extremeRate -> Level.EXTREME
            rate < warnRate -> Level.WARN
            rate < noticeRate -> Level.NOTICE
            else -> Level.OK
        }
        return maxOf(circLevel, assessUse(c))
    }

    fun forgetCircuit(circId: Long) {
        circState.remove(circId)
    }
}

/**
 * Circuit build timeout (C Tor `circuitstats.c` CBT quantile estimate).
 *
 * Maintains a histogram of successful build times and recommends a timeout
 * at [quantile] (default 0.8).
 */
class CircuitBuildTimeout(
    private val quantile: Double = 0.80,
    private val minSamples: Int = 100,
    private val defaultTimeoutMs: Long = 60_000,
    private val maxTimeoutMs: Long = 120_000,
    private val minTimeoutMs: Long = 1_500,
) {
    private val samples = ArrayList<Long>()

    fun addSuccess(buildTimeMs: Long) {
        if (buildTimeMs <= 0) return
        synchronized(samples) {
            samples += buildTimeMs
            if (samples.size > 1000) samples.removeAt(0)
        }
    }

    fun timeoutMs(): Long {
        val sorted = synchronized(samples) { samples.sorted() }
        if (sorted.size < minSamples) return defaultTimeoutMs
        val idx = ((sorted.size - 1) * quantile).toInt().coerceIn(0, sorted.lastIndex)
        return sorted[idx].coerceIn(minTimeoutMs, maxTimeoutMs)
    }

    fun sampleCount(): Int = synchronized(samples) { samples.size }
}
