package org.kotlintor.circuit

import org.kotlintor.dir.Consensus
import java.util.ArrayDeque

/**
 * Shared congestion-control params (C Tor `congestion_control_common.c`).
 *
 * Inventory: `L1:core/or/congestion_control_common.c`
 *
 * Algorithm enums: `CC_ALG_SENDME=0`, `CC_ALG_VEGAS=2` (Westwood/NOLA retired).
 */
object CongestionControlCommon {
    const val CC_ALG_SENDME: Int = 0
    const val CC_ALG_VEGAS: Int = 2

    const val SENDME_INC_DEFAULT: Int = 31
    const val CWND_INIT_DEFAULT: Int = 4 * SENDME_INC_DEFAULT
    const val CWND_MIN_DEFAULT: Int = CWND_INIT_DEFAULT
    const val CWND_INC_DEFAULT: Int = 1
    const val CWND_INC_PCT_SS_DEFAULT: Int = 100
    const val CWND_INC_RATE_DEFAULT: Int = SENDME_INC_DEFAULT
    const val ORCONN_HIGHWATER_DEFAULT: Int = 32 * 1024
    const val ORCONN_LOWWATER_DEFAULT: Int = 16 * 1024

    data class Params(
        val alg: Int = CC_ALG_VEGAS,
        val sendmeInc: Int = SENDME_INC_DEFAULT,
        val cwndInit: Int = CWND_INIT_DEFAULT,
        val cwndMin: Int = CWND_MIN_DEFAULT,
        val cwndInc: Int = CWND_INC_DEFAULT,
        val cwndIncPctSs: Int = CWND_INC_PCT_SS_DEFAULT,
        val cwndIncRate: Int = CWND_INC_RATE_DEFAULT,
        val cwndMax: Int = Int.MAX_VALUE,
        val rttResetPct: Int = 100,
        val bweMin: Int = 5,
        val ewmaCwndPct: Int = 50,
        val ewmaMax: Int = 10,
        val ewmaSs: Int = 2,
        val orconnHighwater: Int = ORCONN_HIGHWATER_DEFAULT,
        val orconnLowwater: Int = ORCONN_LOWWATER_DEFAULT,
    )

    @Volatile private var params: Params = Params()

    fun resetToDefaults() {
        params = Params()
    }

    fun current(): Params = params

    /** C Tor `congestion_control_enabled` — true when alg ≠ SENDME-only. */
    fun enabled(): Boolean = params.alg != CC_ALG_SENDME

    fun setAlgForTests(alg: Int) {
        params = params.copy(alg = if (alg == CC_ALG_SENDME || alg == CC_ALG_VEGAS) alg else CC_ALG_VEGAS)
    }

    /**
     * C Tor consensus update path for `cc_*` / `orconn_*` params.
     */
    fun newConsensus(ns: Consensus?) {
        if (ns == null) return
        var alg = ns.param("cc_alg", CC_ALG_VEGAS.toLong()).toInt()
        if (alg != CC_ALG_SENDME && alg != CC_ALG_VEGAS) alg = CC_ALG_VEGAS
        params = Params(
            alg = alg,
            sendmeInc = ns.param("cc_sendme_inc", SENDME_INC_DEFAULT.toLong()).toInt().coerceIn(1, 254),
            cwndInit = ns.param("cc_cwnd_init", CWND_INIT_DEFAULT.toLong()).toInt().coerceAtLeast(1),
            cwndMin = ns.param("cc_cwnd_min", CWND_MIN_DEFAULT.toLong()).toInt().coerceAtLeast(1),
            cwndInc = ns.param("cc_cwnd_inc", CWND_INC_DEFAULT.toLong()).toInt().coerceAtLeast(1),
            cwndIncPctSs = ns.param("cc_cwnd_inc_pct_ss", CWND_INC_PCT_SS_DEFAULT.toLong()).toInt().coerceIn(1, 500),
            cwndIncRate = ns.param("cc_cwnd_inc_rate", CWND_INC_RATE_DEFAULT.toLong()).toInt().coerceAtLeast(1),
            cwndMax = ns.param("cc_cwnd_max", Int.MAX_VALUE.toLong()).toInt().coerceAtLeast(1),
            rttResetPct = ns.param("cc_rtt_reset_pct", 100).toInt().coerceIn(0, 100),
            bweMin = ns.param("cc_bwe_min", 5).toInt().coerceAtLeast(1),
            ewmaCwndPct = ns.param("cc_ewma_cwnd_pct", 50).toInt().coerceIn(1, 100),
            ewmaMax = ns.param("cc_ewma_max", 10).toInt().coerceAtLeast(1),
            ewmaSs = ns.param("cc_ewma_ss", 2).toInt().coerceAtLeast(1),
            orconnHighwater = ns.param("orconn_high", ORCONN_HIGHWATER_DEFAULT.toLong()).toInt().coerceAtLeast(1),
            orconnLowwater = ns.param("orconn_low", ORCONN_LOWWATER_DEFAULT.toLong()).toInt().coerceAtLeast(1),
        )
    }

    /** Build a [CongestionControl] instance from current consensus params. */
    fun newController(): CongestionControl =
        CongestionControl.fromNegotiatedSendmeInc(params.sendmeInc)

    // --- C Tor congestion_control_common.h op aliases (L3) ---

    private val timestamps = ArrayDeque<Long>()
    @Volatile private var clockStalls: Long = 0
    @Volatile private var rttResets: Long = 0
    @Volatile private var ccDisabledOverride: Boolean? = null

    data class ControlPortFields(
        val cwnd: Int,
        val inflight: Int,
        val sendmeInc: Int,
        val alg: Int,
    )

    /** C Tor `circuit_sent_cell_for_sendme`. */
    fun circuitSentCellForSendme(cellsSinceSendme: Int, inc: Int = params.sendmeInc): Boolean =
        cellsSinceSendme > 0 && cellsSinceSendme % inc == 0

    /** C Tor `congestion_control_build_ext_request`. */
    fun congestionControlBuildExtRequest(sendmeInc: Int = params.sendmeInc): ByteArray =
        byteArrayOf(1, sendmeInc.toByte())

    /** C Tor `congestion_control_build_ext_response`. */
    fun congestionControlBuildExtResponse(sendmeInc: Int = params.sendmeInc): ByteArray =
        byteArrayOf(1, sendmeInc.toByte())

    /** C Tor `congestion_control_dispatch_cc_alg`. */
    fun congestionControlDispatchCcAlg(): Int = params.alg

    /** C Tor `congestion_control_enabled`. */
    fun congestionControlEnabled(): Boolean =
        ccDisabledOverride?.not() ?: enabled()

    /** C Tor `congestion_control_free_`. */
    fun congestionControlFree(cc: CongestionControl?) {
        cc ?: return
    }

    /** C Tor `congestion_control_get_control_port_fields`. */
    fun congestionControlGetControlPortFields(cc: CongestionControl): ControlPortFields =
        ControlPortFields(cc.congestionWindow, cc.inFlight, cc.increment, params.alg)

    /** C Tor `congestion_control_get_num_clock_stalls`. */
    fun congestionControlGetNumClockStalls(): Long = clockStalls

    /** C Tor `congestion_control_get_num_rtt_reset`. */
    fun congestionControlGetNumRttReset(): Long = rttResets

    /** C Tor `congestion_control_get_package_window`. */
    fun congestionControlGetPackageWindow(cc: CongestionControl): Int =
        (cc.congestionWindow - cc.inFlight).coerceAtLeast(0)

    /** C Tor `congestion_control_new`. */
    fun congestionControlNew(): CongestionControl = newController()

    /** C Tor `congestion_control_new_consensus_params`. */
    fun congestionControlNewConsensusParams(ns: org.kotlintor.dir.Consensus?) = newConsensus(ns)

    /** C Tor `congestion_control_note_cell_sent`. */
    fun congestionControlNoteCellSent(nowNs: Long = System.nanoTime()) {
        timestamps.addLast(nowNs)
        while (timestamps.size > 10_000) timestamps.removeFirst()
    }

    /** C Tor `congestion_control_parse_ext_request`. */
    fun congestionControlParseExtRequest(data: ByteArray): Int =
        if (data.size >= 2) data[1].toInt() and 0xff else SENDME_INC_DEFAULT

    /** C Tor `congestion_control_parse_ext_response`. */
    fun congestionControlParseExtResponse(data: ByteArray): Int =
        congestionControlParseExtRequest(data)

    /** C Tor `congestion_control_set_cc_disabled`. */
    fun congestionControlSetCcDisabled() {
        ccDisabledOverride = true
        setAlgForTests(CC_ALG_SENDME)
    }

    /** C Tor `congestion_control_set_cc_enabled`. */
    fun congestionControlSetCcEnabled() {
        ccDisabledOverride = false
        setAlgForTests(CC_ALG_VEGAS)
    }

    /** C Tor `congestion_control_update_circuit_estimates`. */
    fun congestionControlUpdateCircuitEstimates(rttEwma: Long, rttMin: Long): Long =
        if (rttMin <= 0) rttEwma else (rttEwma * 7 + rttMin) / 8

    /** C Tor `congestion_control_update_circuit_rtt`. */
    fun congestionControlUpdateCircuitRtt(prevEwma: Long, sample: Long): Long {
        if (sample <= 0) {
            rttResets++
            return prevEwma
        }
        return if (prevEwma == 0L) sample else (prevEwma * 7 + sample) / 8
    }

    /** C Tor `congestion_control_validate_sendme_increment`. */
    fun congestionControlValidateSendmeIncrement(inc: Int): Boolean = inc in 1..254

    /** C Tor `enqueue_timestamp`. */
    fun enqueueTimestamp(t: Long = System.nanoTime()) = congestionControlNoteCellSent(t)

    /** C Tor `is_monotime_clock_reliable`. */
    fun isMonotimeClockReliable(): Boolean = true

    /** C Tor `percent_max_mix`. */
    fun percentMaxMix(a: Long, b: Long, pct: Int): Long {
        val p = pct.coerceIn(0, 100)
        val hi = maxOf(a, b)
        val lo = minOf(a, b)
        return lo + (hi - lo) * p / 100
    }

    /** C Tor `sendme_get_inc_count`. */
    fun sendmeGetIncCount(): Int = params.sendmeInc

    /** C Tor `time_delta_stalled_or_jumped`. */
    fun timeDeltaStalledOrJumped(deltaNs: Long, stallThresholdNs: Long = 1_000_000_000L): Boolean {
        if (deltaNs < 0 || deltaNs > stallThresholdNs) {
            clockStalls++
            return true
        }
        return false
    }
}
