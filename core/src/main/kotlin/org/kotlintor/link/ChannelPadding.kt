package org.kotlintor.link

import org.kotlintor.util.SecureRandomSource

/**
 * Channel padding / netflow decision machine (C Tor `channelpadding.c`).
 *
 * Complements [PaddingNegotiate] cell codecs: decides *when* to emit PADDING
 * given idle time and consensus-style `nf_*` parameters.
 */
enum class ChannelPaddingDecision {
    WONT_PAD,
    PAD_LATER,
    PADDING_SCHEDULED,
    PADDING_ALREADY_SCHEDULED,
    PADDING_SENT,
}

data class ChannelPaddingParams(
    val itoLowMs: Int = 1_500,
    val itoHighMs: Int = 9_500,
    val itoLowReducedMs: Int = 9_000,
    val itoHighReducedMs: Int = 14_000,
    val connTimeoutRelaysSec: Int = 3_600,
    val connTimeoutClientsSec: Int = 1_800,
    val padBeforeUsage: Boolean = true,
    val padRelays: Boolean = true,
    val padSingleOnion: Boolean = true,
    val reduced: Boolean = false,
) {
    fun itoLow(): Int = if (reduced) itoLowReducedMs else itoLowMs
    fun itoHigh(): Int = if (reduced) itoHighReducedMs else itoHighMs

    companion object {
        /** Parse consensus params (`nf_ito_low` etc.) from a map. */
        fun fromConsensus(params: Map<String, Int>, reduced: Boolean = false): ChannelPaddingParams {
            fun g(k: String, d: Int) = params[k] ?: d
            return ChannelPaddingParams(
                itoLowMs = g("nf_ito_low", 1_500),
                itoHighMs = g("nf_ito_high", 9_500),
                itoLowReducedMs = g("nf_ito_low_reduced", 9_000),
                itoHighReducedMs = g("nf_ito_high_reduced", 14_000),
                connTimeoutRelaysSec = g("nf_conntimeout_relays", 3_600),
                connTimeoutClientsSec = g("nf_conntimeout_clients", 1_800),
                padBeforeUsage = g("nf_pad_before_usage", 1) != 0,
                padRelays = g("nf_pad_relays", 1) != 0,
                padSingleOnion = g("nf_pad_single_onion", 1) != 0,
                reduced = reduced,
            )
        }
    }
}

class ChannelPaddingController(
    var params: ChannelPaddingParams = ChannelPaddingParams(),
    var enabled: Boolean = true,
    var isClientChannel: Boolean = true,
    var hasCircuitUsage: Boolean = false,
) {
    @Volatile var lastCellAtMs: Long = System.currentTimeMillis()
        private set
    @Volatile private var scheduledAtMs: Long = 0
    @Volatile private var paddingDisabled: Boolean = false

    fun noteCellActivity(nowMs: Long = System.currentTimeMillis()) {
        lastCellAtMs = nowMs
        scheduledAtMs = 0
    }

    fun disable() {
        paddingDisabled = true
        enabled = false
        scheduledAtMs = 0
    }

    fun reduce() {
        params = params.copy(reduced = true)
    }

    fun applyNegotiate(cmd: Int, lowMs: Int, highMs: Int) {
        when (cmd) {
            PaddingNegotiate.COMMAND_STOP -> disable()
            PaddingNegotiate.COMMAND_START -> {
                paddingDisabled = false
                enabled = true
                params = params.copy(
                    itoLowMs = lowMs.coerceAtLeast(0),
                    itoHighMs = highMs.coerceAtLeast(lowMs),
                    reduced = false,
                )
            }
        }
    }

    /** Single Onion Service reduced padding (C Tor `nf_pad_single_onion` / SOS). */
    fun applySingleOnionService() {
        if (!params.padSingleOnion) {
            disable()
            return
        }
        reduce()
    }

    /**
     * Decide whether to send padding now. Matches C Tor decision enum subset.
     */
    fun decide(nowMs: Long = System.currentTimeMillis()): ChannelPaddingDecision {
        if (!enabled || paddingDisabled) return ChannelPaddingDecision.WONT_PAD
        if (!params.padBeforeUsage && !hasCircuitUsage && isClientChannel) {
            return ChannelPaddingDecision.WONT_PAD
        }
        if (!isClientChannel && !params.padRelays) return ChannelPaddingDecision.WONT_PAD

        val idle = nowMs - lastCellAtMs
        val low = params.itoLow().toLong()
        val high = params.itoHigh().toLong().coerceAtLeast(low)
        if (idle < low) return ChannelPaddingDecision.PAD_LATER

        if (scheduledAtMs == 0L) {
            val span = (high - low).coerceAtLeast(0)
            val delay = if (span == 0L) 0L else SecureRandomSource.nextInt((span + 1).toInt()).toLong()
            scheduledAtMs = lastCellAtMs + low + delay
            return ChannelPaddingDecision.PADDING_SCHEDULED
        }
        if (nowMs < scheduledAtMs) return ChannelPaddingDecision.PADDING_ALREADY_SCHEDULED
        scheduledAtMs = 0
        lastCellAtMs = nowMs
        return ChannelPaddingDecision.PADDING_SENT
    }

    /** Next delay before re-checking (ms). */
    fun nextCheckDelayMs(nowMs: Long = System.currentTimeMillis()): Long {
        val low = params.itoLow().toLong()
        val idle = nowMs - lastCellAtMs
        if (idle < low) return (low - idle).coerceAtLeast(50)
        if (scheduledAtMs > nowMs) return (scheduledAtMs - nowMs).coerceAtLeast(50)
        return 250
    }
}

/**
 * Naming primary facade for `channelpadding_*` L3 ops.
 */
object ChannelPadding {
    fun newController(
        params: ChannelPaddingParams = ChannelPaddingParams(),
        isClient: Boolean = true,
    ): ChannelPaddingController =
        ChannelPaddingController(params = params, isClientChannel = isClient)

    /** C Tor `channelpadding_decide_to_pad_channel`. */
    fun decideToPadChannel(
        ctrl: ChannelPaddingController,
        nowMs: Long = System.currentTimeMillis(),
    ): ChannelPaddingDecision = ctrl.decide(nowMs)

    /** C Tor `channelpadding_disable_padding_on_channel`. */
    fun disablePaddingOnChannel(ctrl: ChannelPaddingController) = ctrl.disable()

    /** C Tor `channelpadding_get_channel_idle_timeout` — midpoint of ito range (ms→sec). */
    fun getChannelIdleTimeout(params: ChannelPaddingParams): Int =
        ((params.itoLow() + params.itoHigh()) / 2 / 1000).coerceAtLeast(1)

    /** C Tor `channelpadding_get_circuits_available_timeout`. */
    fun getCircuitsAvailableTimeout(params: ChannelPaddingParams, client: Boolean): Int =
        if (client) params.connTimeoutClientsSec else params.connTimeoutRelaysSec

    fun logHeartbeat(ctrl: ChannelPaddingController): String =
        "pad enabled=${ctrl.enabled} lastCell=${ctrl.lastCellAtMs}"

    /** C Tor `channelpadding_new_consensus_params`. */
    fun newConsensusParams(params: Map<String, Int>, reduced: Boolean = false): ChannelPaddingParams =
        ChannelPaddingParams.fromConsensus(params, reduced)

    /** C Tor `channelpadding_reduce_padding_on_channel`. */
    fun reducePaddingOnChannel(ctrl: ChannelPaddingController) = ctrl.reduce()

    /** C Tor `channelpadding_send_enable_command` — START negotiate payload. */
    fun sendEnableCommand(lowMs: Int = 1_500, highMs: Int = 9_500): ByteArray {
        ctrlApplyStart(lowMs, highMs)
        return byteArrayOf(
            PaddingNegotiate.COMMAND_START.toByte(),
            ((lowMs ushr 8) and 0xff).toByte(),
            (lowMs and 0xff).toByte(),
            ((highMs ushr 8) and 0xff).toByte(),
            (highMs and 0xff).toByte(),
        )
    }

    private fun ctrlApplyStart(lowMs: Int, highMs: Int) {
        // encoding-only helper; controller apply is via [updatePaddingForChannel]
        require(highMs >= lowMs)
    }

    /** C Tor `channelpadding_update_padding_for_channel`. */
    fun updatePaddingForChannel(
        ctrl: ChannelPaddingController,
        cmd: Int,
        lowMs: Int,
        highMs: Int,
    ) = ctrl.applyNegotiate(cmd, lowMs, highMs)
}
