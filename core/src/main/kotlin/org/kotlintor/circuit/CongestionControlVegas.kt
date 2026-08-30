package org.kotlintor.circuit

/**
 * Vegas congestion-control parameters and queue_use update (C Tor `congestion_control_vegas.c`).
 *
 * Inventory: `L1:core/or/congestion_control_vegas.c`
 *
 * OUTBUF_CELLS defaults to the negotiated SENDME increment (typically 31).
 */
object CongestionControlVegas {
    const val SS_CWND_MAX_DEFAULT: Int = 5000
    const val CWND_FULL_GAP_DEFAULT: Int = 4
    const val CWND_FULL_MINPCT_DEFAULT: Int = 25
    const val CWND_FULL_PER_CWND_DEFAULT: Int = 1

    enum class PathKind { EXIT, ONION, SBWS }

    data class Params(
        val alpha: Int,
        val beta: Int,
        val gamma: Int,
        val delta: Int,
        val ssCwndMax: Int = SS_CWND_MAX_DEFAULT,
        val cwndFullGap: Int = CWND_FULL_GAP_DEFAULT,
        val cwndFullMinPct: Int = CWND_FULL_MINPCT_DEFAULT,
        val cwndFullPerCwnd: Int = CWND_FULL_PER_CWND_DEFAULT,
    )

    /** Exit defaults: α=3·N β=4·N γ=3·N δ=5·N (N = OUTBUF_CELLS). */
    fun exitParams(outbufCells: Int = 31): Params = Params(
        alpha = 3 * outbufCells,
        beta = 4 * outbufCells,
        gamma = 3 * outbufCells,
        delta = 5 * outbufCells,
    )

    fun onionParams(outbufCells: Int = 31): Params = Params(
        alpha = 3 * outbufCells,
        beta = 6 * outbufCells,
        gamma = 4 * outbufCells,
        delta = 7 * outbufCells,
    )

    /** SBWS uses TLS_RECORD_MAX_CELLS ≈ 31 for the ±TLS term. */
    fun sbwsParams(outbufCells: Int = 31, tlsRecordMaxCells: Int = 31): Params = Params(
        alpha = 2 * outbufCells - tlsRecordMaxCells,
        beta = 2 * outbufCells + tlsRecordMaxCells,
        gamma = 2 * outbufCells,
        delta = 4 * outbufCells,
    )

    fun paramsFor(kind: PathKind, outbufCells: Int = 31): Params = when (kind) {
        PathKind.EXIT -> exitParams(outbufCells)
        PathKind.ONION -> onionParams(outbufCells)
        PathKind.SBWS -> sbwsParams(outbufCells)
    }

    /**
     * queue_use ≈ cwnd * (1 - rtt_min/rtt_ewma) when EWMA exceeds min RTT.
     */
    fun queueUse(cwnd: Int, rttMinMs: Long, rttEwmaMs: Long): Int {
        if (rttMinMs == Long.MAX_VALUE || rttEwmaMs <= 0 || rttEwmaMs <= rttMinMs) return 0
        return ((cwnd.toLong() * (rttEwmaMs - rttMinMs)) / rttEwmaMs).toInt()
    }

    data class VegasUpdate(
        val newCwnd: Int,
        val inSlowStart: Boolean,
    )

    /**
     * One Vegas SENDME-driven cwnd update (exit defaults).
     */
    fun updateCwnd(
        cwnd: Int,
        queueUse: Int,
        inSlowStart: Boolean,
        params: Params,
        sendmeInc: Int,
        cwndInc: Int = sendmeInc,
        cwndMin: Int = sendmeInc,
        cwndMax: Int = params.ssCwndMax,
    ): VegasUpdate {
        if (inSlowStart) {
            return if (queueUse > params.delta) {
                VegasUpdate((cwnd * 3 / 4).coerceAtLeast(cwndMin), inSlowStart = false)
            } else {
                VegasUpdate((cwnd + sendmeInc).coerceAtMost(cwndMax), inSlowStart = true)
            }
        }
        val next = when {
            queueUse < params.alpha -> (cwnd + cwndInc).coerceAtMost(cwndMax)
            queueUse > params.beta -> (cwnd - cwndInc).coerceAtLeast(cwndMin)
            else -> cwnd
        }
        return VegasUpdate(next, inSlowStart = false)
    }

    /** C Tor `congestion_control_vegas_set_params`. */
    fun congestionControlVegasSetParams(kind: PathKind, outbufCells: Int = 31): Params =
        paramsFor(kind, outbufCells)

    /**
     * C Tor `congestion_control_vegas_process_sendme` — apply one SENDME Vegas step.
     */
    fun congestionControlVegasProcessSendme(
        cwnd: Int,
        rttMinMs: Long,
        rttEwmaMs: Long,
        inSlowStart: Boolean,
        params: Params = exitParams(),
        sendmeInc: Int = 31,
    ): VegasUpdate {
        val q = queueUse(cwnd, rttMinMs, rttEwmaMs)
        return updateCwnd(cwnd, q, inSlowStart, params, sendmeInc)
    }
}
