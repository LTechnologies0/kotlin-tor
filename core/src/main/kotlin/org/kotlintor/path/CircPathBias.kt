package org.kotlintor.path

import org.kotlintor.config.PathBiasOptions
import org.kotlintor.config.TorConfig

/**
 * Circuit path-bias tracker (C Tor `circpathbias.c` / `circpathbias.h`).
 *
 * Inventory: `L1:feature/client/circpathbias.c`
 *
 * Implementation: [PathBiasTracker]. This object is the naming-aligned entry.
 */
object CircPathBias {
    /** Default tracker used by C Tor-named aliases when no instance is passed. */
    private val defaultTracker = PathBiasTracker()

    fun newTracker(opts: PathBiasOptions = PathBiasOptions()): PathBiasTracker =
        PathBiasTracker(opts)

    fun newTracker(
        noticeRate: Double = 0.70,
        warnRate: Double = 0.50,
        extremeRate: Double = 0.30,
        dropGuards: Boolean = false,
    ): PathBiasTracker =
        PathBiasTracker(
            noticeRate = noticeRate,
            warnRate = warnRate,
            extremeRate = extremeRate,
            dropGuards = dropGuards,
        )

    fun defaultTracker(): PathBiasTracker = defaultTracker

    /** C Tor `pathbias_get_extreme_rate`. */
    fun pathbiasGetExtremeRate(opts: PathBiasOptions = PathBiasOptions()): Double = opts.extremeRate

    fun pathbiasGetExtremeRate(config: TorConfig): Double = config.pathBias.extremeRate

    /** C Tor `pathbias_get_extreme_use_rate`. */
    fun pathbiasGetExtremeUseRate(opts: PathBiasOptions = PathBiasOptions()): Double = opts.extremeUseRate

    fun pathbiasGetExtremeUseRate(config: TorConfig): Double = config.pathBias.extremeUseRate

    /** C Tor `pathbias_get_dropguards`. */
    fun pathbiasGetDropguards(opts: PathBiasOptions = PathBiasOptions()): Boolean = opts.dropGuards

    fun pathbiasGetDropguards(config: TorConfig): Boolean = config.pathBias.dropGuards

    /** C Tor `pathbias_count_build_attempt`. */
    fun pathbiasCountBuildAttempt(
        circId: Long,
        guardFp: String,
        tracker: PathBiasTracker = defaultTracker,
    ): Int {
        tracker.markBuildAttempted(circId, guardFp)
        return tracker.counters(guardFp).circAttempted
    }

    /** C Tor `pathbias_count_build_success`. */
    fun pathbiasCountBuildSuccess(
        circId: Long,
        guardFp: String,
        tracker: PathBiasTracker = defaultTracker,
    ) {
        tracker.markBuildSucceeded(circId, guardFp)
    }

    /** C Tor `pathbias_count_timeout` — treat as failed use for rate accounting. */
    fun pathbiasCountTimeout(
        circId: Long,
        guardFp: String,
        tracker: PathBiasTracker = defaultTracker,
    ) {
        tracker.markUseFailed(circId, guardFp)
    }

    /** C Tor `pathbias_count_use_attempt`. */
    fun pathbiasCountUseAttempt(
        circId: Long,
        guardFp: String,
        tracker: PathBiasTracker = defaultTracker,
    ) {
        tracker.markUseAttempted(circId, guardFp)
    }

    /** C Tor `pathbias_mark_use_success`. */
    fun pathbiasMarkUseSuccess(
        circId: Long,
        guardFp: String,
        tracker: PathBiasTracker = defaultTracker,
    ) {
        tracker.markUseSucceeded(circId, guardFp)
    }

    /** C Tor `pathbias_mark_use_rollback`. */
    fun pathbiasMarkUseRollback(
        circId: Long,
        tracker: PathBiasTracker = defaultTracker,
    ) {
        tracker.markUseRollback(circId)
    }

    /**
     * C Tor `pathbias_check_close` — returns 1 when close should count against the guard.
     */
    fun pathbiasCheckClose(
        circId: Long,
        reason: Int,
        guardFp: String,
        tracker: PathBiasTracker = defaultTracker,
    ): Int {
        val st = tracker.state(circId)
        // Measure-only closes after build attempt without success.
        if (st == PathState.BUILD_ATTEMPTED || st == PathState.USE_ATTEMPTED) {
            tracker.markUseFailed(circId, guardFp)
            return 1
        }
        tracker.forgetCircuit(circId)
        return 0
    }

    /**
     * C Tor `pathbias_check_probe_response` — 1 if probe cell looks like a valid PADDING reply.
     */
    fun pathbiasCheckProbeResponse(relayCommandId: Int): Int =
        if (relayCommandId == 0 /* PADDING */ || relayCommandId == 128 /* DROP */) 1 else 0

    /** C Tor `pathbias_count_valid_cells` — bump use success when DATA cells arrive. */
    fun pathbiasCountValidCells(
        circId: Long,
        guardFp: String,
        cellCount: Int = 1,
        tracker: PathBiasTracker = defaultTracker,
    ) {
        if (cellCount <= 0) return
        if (tracker.state(circId) == PathState.USE_ATTEMPTED) {
            tracker.markUseSucceeded(circId, guardFp)
        }
    }

    /** C Tor `pathbias_state_to_string`. */
    fun pathbiasStateToString(state: PathState): String =
        when (state) {
            PathState.NEW_CIRC -> "new"
            PathState.BUILD_ATTEMPTED -> "build attempted"
            PathState.BUILD_SUCCEEDED -> "build succeeded"
            PathState.USE_ATTEMPTED -> "use attempted"
            PathState.USE_SUCCEEDED -> "use succeeded"
            PathState.USE_FAILED -> "use failed"
            PathState.ALREADY_COUNTED -> "already counted"
        }
}
