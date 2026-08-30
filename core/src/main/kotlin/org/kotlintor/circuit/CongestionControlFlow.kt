package org.kotlintor.circuit

import org.kotlintor.util.u32be

/**
 * Prop324 edge stream flow control (C Tor `congestion_control_flow.c`).
 *
 * Inventory: `L1:core/or/congestion_control_flow.c`
 *
 * C Tor APIs: `flow_control_new_consensus_params`, `flow_control_decide_xoff`,
 * `flow_control_decide_xon`, `flow_control_note_sent_data`, `edge_uses_flow_control`.
 */
object CongestionControlFlow {
    const val CELL_PAYLOAD_SIZE = 509
    const val RELAY_HEADER_SIZE_V0 = 11
    const val RELAY_HEADER_SIZE_V1_WITH_STREAM_ID = 16 + 1 + 2 + 2
    const val RELAY_PAYLOAD_SIZE_MAX = CELL_PAYLOAD_SIZE - RELAY_HEADER_SIZE_V0 // 498
    const val RELAY_PAYLOAD_SIZE_MIN = CELL_PAYLOAD_SIZE - RELAY_HEADER_SIZE_V1_WITH_STREAM_ID // 488
    const val XOFF_GRACE_PERIOD_USEC = 5_000L
    const val MAX_EXPECTED_CELL_BURST = 32

    data class ConsensusParams(
        val xoffClient: Int = 500 * RELAY_PAYLOAD_SIZE_MIN,
        val xoffExit: Int = 500 * RELAY_PAYLOAD_SIZE_MIN,
        val xonChangePct: Int = 25,
        val xonRateBytes: Int = 500 * RELAY_PAYLOAD_SIZE_MAX,
        val xonEwmaCnt: Int = 2,
    )

    @Volatile
    var params: ConsensusParams = ConsensusParams()
        private set

    var numXoffSent: Long = 0
        private set
    var numXonSent: Long = 0
        private set

    /** C Tor `flow_control_new_consensus_params`. */
    fun flowControlNewConsensusParams(ns: Map<String, Long>) = newConsensusParams(ns)

    fun newConsensusParams(ns: Map<String, Long>) {
        fun p(name: String, dflt: Long, min: Long, max: Long): Long {
            val v = ns[name] ?: dflt
            return v.coerceIn(min, max)
        }
        params = ConsensusParams(
            xoffClient = (p("cc_xoff_client", 500, 1, 10_000) * RELAY_PAYLOAD_SIZE_MIN).toInt(),
            xoffExit = (p("cc_xoff_exit", 500, 1, 10_000) * RELAY_PAYLOAD_SIZE_MIN).toInt(),
            xonChangePct = p("cc_xon_change_pct", 25, 1, 99).toInt(),
            xonRateBytes = (p("cc_xon_rate", 500, 1, 5_000) * RELAY_PAYLOAD_SIZE_MAX).toInt(),
            xonEwmaCnt = p("cc_xon_ewma_cnt", 2, 2, 100).toInt(),
        )
    }

    fun resetStats() {
        numXoffSent = 0
        numXonSent = 0
    }

    /** C Tor `edge_uses_flow_control`. */
    fun edgeUsesFlowControl(usesCc: Boolean): Boolean = usesCc

    /** C Tor `conn_uses_flow_control`. */
    fun connUsesFlowControl(usesCc: Boolean): Boolean = usesCc

    /** Encode trunnel `xoff_cell` (version 0). */
    fun encodeXoff(version: Int = 0): ByteArray = byteArrayOf(version.toByte())

    /** Encode trunnel `xon_cell` (version 0 + kbps_ewma u32be). */
    fun encodeXon(kbpsEwma: Int, version: Int = 0): ByteArray =
        byteArrayOf(version.toByte()) + u32be(kbpsEwma.toLong() and 0xffff_ffffL)

    fun parseXoff(payload: ByteArray): Int? =
        if (payload.isNotEmpty() && payload[0].toInt() and 0xff == 0) 0 else null

    fun parseXon(payload: ByteArray): Int? {
        if (payload.size < 5 || payload[0].toInt() and 0xff != 0) return null
        val b = payload
        return ((b[1].toInt() and 0xff) shl 24) or
            ((b[2].toInt() and 0xff) shl 16) or
            ((b[3].toInt() and 0xff) shl 8) or
            (b[4].toInt() and 0xff)
    }

    enum class EdgeKind { CLIENT_OR_HS, EXIT }

    /** Per-edge state mirroring fields used by `flow_control_decide_xoff/xon`. */
    class EdgeState(
        val kind: EdgeKind,
        var outbufLen: Int = 0,
        var usesFlowControl: Boolean = true,
    ) {
        var xoffSent: Boolean = false
        var xoffGraceStartUsec: Long = 0
        var drainStartUsec: Long = 0
        var drainedBytes: Long = 0
        var prevDrainedBytes: Long = 0
        var ewmaDrainRate: Int = 0
        var ewmaRateLastSent: Int = 0
        var pendingXoff: ByteArray? = null
        var pendingXon: ByteArray? = null
        /** True after peer sent XOFF until XON clears it. */
        var peerXoff: Boolean = false
    }

    /**
     * C Tor `circuit_process_stream_xoff` — peer asks us to stop sending.
     * Returns true when the cell is accepted.
     */
    fun circuitProcessStreamXoff(stream: EdgeState, payload: ByteArray = encodeXoff()): Boolean {
        if (parseXoff(payload) == null) return false
        stream.peerXoff = true
        return true
    }

    /**
     * C Tor `circuit_process_stream_xon` — peer resumes / updates rate.
     * Returns true when the cell is accepted.
     */
    fun circuitProcessStreamXon(stream: EdgeState, payload: ByteArray): Boolean {
        val rate = parseXon(payload) ?: return false
        stream.peerXoff = false
        stream.ewmaDrainRate = rate
        return true
    }

    /** C Tor `flow_control_decide_xoff`. */
    fun flowControlDecideXoff(stream: EdgeState, nowUsec: Long = System.nanoTime() / 1_000): Int =
        decideXoff(stream, nowUsec)

    fun decideXoff(stream: EdgeState, nowUsec: Long = System.nanoTime() / 1_000): Int {
        if (!edgeUsesFlowControl(stream.usesFlowControl)) return -1
        val limit = if (stream.kind == EdgeKind.CLIENT_OR_HS) params.xoffClient else params.xoffExit
        val total = stream.outbufLen
        if (total > limit) {
            if (!stream.xoffSent) {
                if (stream.xoffGraceStartUsec == 0L) {
                    stream.xoffGraceStartUsec = nowUsec
                } else if (nowUsec > stream.xoffGraceStartUsec + XOFF_GRACE_PERIOD_USEC) {
                    stream.pendingXoff = encodeXoff()
                    stream.xoffSent = true
                    numXoffSent++
                    stream.ewmaDrainRate = 0
                    stream.xoffGraceStartUsec = 0
                }
            }
        } else {
            stream.xoffGraceStartUsec = 0
        }
        if (total > MAX_EXPECTED_CELL_BURST * RELAY_PAYLOAD_SIZE_MIN) {
            decideXon(stream, nWritten = 0, nowUsec = nowUsec)
        }
        return 0
    }

    /** C Tor `compute_drain_rate` → KB/sec. */
    fun computeDrainRate(stream: EdgeState, nowUsec: Long): Int {
        if (stream.drainStartUsec == 0L) return 0
        val delta = nowUsec - stream.drainStartUsec
        if (delta <= 0L) return 0
        val rate = (stream.prevDrainedBytes * 1000L) / delta
        return rate.coerceIn(1, Int.MAX_VALUE.toLong()).toInt()
    }

    private fun drainRateChanged(stream: EdgeState): Boolean {
        if (stream.ewmaRateLastSent == 0) return false
        val pct = params.xonChangePct.toLong()
        val last = stream.ewmaRateLastSent.toLong()
        val cur = stream.ewmaDrainRate.toLong()
        if (cur > (100 + pct) * last / 100) return true
        if (cur < (100 - pct) * last / 100) return true
        return false
    }

    private fun nCountEwma(sample: Int, avg: Int, n: Int): Int {
        if (avg == 0) return sample
        return ((sample.toLong() + (n - 1).toLong() * avg) / n).toInt()
    }

    /** C Tor `flow_control_decide_xon`. */
    fun flowControlDecideXon(stream: EdgeState, nWritten: Int, nowUsec: Long = System.nanoTime() / 1_000) =
        decideXon(stream, nWritten, nowUsec)

    fun decideXon(stream: EdgeState, nWritten: Int, nowUsec: Long = System.nanoTime() / 1_000) {
        val total = stream.outbufLen
        if (stream.drainedBytes >= Int.MAX_VALUE - nWritten) {
            stream.drainedBytes /= 2
            if (stream.drainStartUsec != 0L) {
                stream.drainStartUsec = nowUsec - (nowUsec - stream.drainStartUsec) / 2
            }
        }
        stream.drainedBytes += nWritten.toLong()

        if (stream.drainStartUsec == 0L && total > 0) {
            stream.drainStartUsec = nowUsec
            stream.drainedBytes = 0
        }

        if (stream.drainStartUsec != 0L && stream.drainedBytes > params.xonRateBytes) {
            if (stream.prevDrainedBytes == 0L) {
                stream.prevDrainedBytes = stream.drainedBytes
            }
            val drainRate = computeDrainRate(stream, nowUsec)
            stream.prevDrainedBytes = stream.drainedBytes
            if (drainRate > 0) {
                stream.ewmaDrainRate = nCountEwma(drainRate, stream.ewmaDrainRate, params.xonEwmaCnt)
                stream.drainedBytes = 0
                stream.drainStartUsec = 0
            }
        }

        val belowXoff = total <= if (stream.kind == EdgeKind.CLIENT_OR_HS) params.xoffClient else params.xoffExit
        val shouldXon = when {
            stream.xoffSent && belowXoff -> true
            !stream.xoffSent && drainRateChanged(stream) && stream.ewmaDrainRate > 0 -> true
            else -> false
        }
        if (shouldXon) {
            stream.pendingXon = encodeXon(stream.ewmaDrainRate)
            stream.ewmaRateLastSent = stream.ewmaDrainRate
            stream.xoffSent = false
            numXonSent++
        }
    }

    /** C Tor `flow_control_note_sent_data`. */
    fun flowControlNoteSentData(stream: EdgeState, len: Int) = noteSentData(stream, len)

    fun noteSentData(stream: EdgeState, len: Int) {
        stream.outbufLen = (stream.outbufLen + len).coerceAtLeast(0)
    }
}

/** Historical alias — prefer [CongestionControlFlow]. */
typealias StreamFlowControl = CongestionControlFlow
