package org.kotlintor.circuit

import org.kotlintor.config.TorConfig
import org.kotlintor.dir.Consensus
import org.kotlintor.relay.RouterMode

/**
 * Conflux consensus/torrc parameters (C Tor `conflux_params.c`).
 *
 * Inventory: `L1:core/or/conflux_params.c`
 */
object ConfluxParams {
    const val ENABLED_DEFAULT: Int = 1
    const val MAX_LINKED_SET_DEFAULT: Int = 10
    const val MAX_PREBUILT_SET_DEFAULT: Int = 3
    const val MAX_UNLINKED_LEG_RETRY_DEFAULT: Int = 3
    const val NUM_LEGS_SET_DEFAULT: Int = 2
    const val MAX_LEGS_SET_DEFAULT: Int = 8
    const val SEND_PCT_DEFAULT: Int = 100
    const val DRAIN_PCT_DEFAULT: Int = 0
    const val LOW_EXIT_THRESHOLD_DEFAULT: Int = 6000 // /10000 → 0.60
    const val MAX_OOO_QUEUE_BYTES_DEFAULT: Int = Int.MAX_VALUE

    @Volatile private var enabled: Boolean = ENABLED_DEFAULT != 0
    @Volatile private var maxLinkedSet: Int = MAX_LINKED_SET_DEFAULT
    @Volatile private var maxPrebuiltSet: Int = MAX_PREBUILT_SET_DEFAULT
    @Volatile private var maxUnlinkedLegRetry: Int = MAX_UNLINKED_LEG_RETRY_DEFAULT
    @Volatile private var numLegsSet: Int = NUM_LEGS_SET_DEFAULT
    @Volatile private var maxLegsSet: Int = MAX_LEGS_SET_DEFAULT
    @Volatile private var drainPct: Int = DRAIN_PCT_DEFAULT
    @Volatile private var sendPct: Int = SEND_PCT_DEFAULT
    @Volatile private var maxOooq: Int = MAX_OOO_QUEUE_BYTES_DEFAULT
    @Volatile private var lowExitThresholdRatio: Double =
        LOW_EXIT_THRESHOLD_DEFAULT / 10_000.0
    @Volatile private var exitConfluxRatio: Double = 0.0

    fun resetToDefaults() {
        enabled = ENABLED_DEFAULT != 0
        maxLinkedSet = MAX_LINKED_SET_DEFAULT
        maxPrebuiltSet = MAX_PREBUILT_SET_DEFAULT
        maxUnlinkedLegRetry = MAX_UNLINKED_LEG_RETRY_DEFAULT
        numLegsSet = NUM_LEGS_SET_DEFAULT
        maxLegsSet = MAX_LEGS_SET_DEFAULT
        drainPct = DRAIN_PCT_DEFAULT
        sendPct = SEND_PCT_DEFAULT
        maxOooq = MAX_OOO_QUEUE_BYTES_DEFAULT
        lowExitThresholdRatio = LOW_EXIT_THRESHOLD_DEFAULT / 10_000.0
        exitConfluxRatio = 0.0
    }

    /** C Tor `conflux_is_enabled` (config + consensus; circ CC check optional). */
    fun isEnabled(
        config: TorConfig,
        congestionControlEnabled: Boolean = CongestionControlCommon.enabled(),
        circuitHasCc: Boolean? = null,
    ): Boolean {
        if (!congestionControlEnabled) return false
        if (circuitHasCc == false) return false
        val torrc = config.runtime.confluxEnabled
        if (!torrc) return false
        return enabled
    }

    /** C Tor `conflux_is_enabled` alias. */
    fun confluxIsEnabled(
        config: TorConfig,
        congestionControlEnabled: Boolean = CongestionControlCommon.enabled(),
        circuitHasCc: Boolean? = null,
    ): Boolean = isEnabled(config, congestionControlEnabled, circuitHasCc)

    fun getMaxLinkedSet(): Int = maxLinkedSet
    fun getMaxPrebuilt(): Int =
        when {
            exitConfluxRatio <= 0.0 -> 0
            exitConfluxRatio < lowExitThresholdRatio -> 1
            else -> maxPrebuiltSet
        }
    fun getMaxUnlinkedLegRetry(): Int = maxUnlinkedLegRetry
    fun getNumLegsSet(): Int = numLegsSet
    fun getMaxLegsSet(): Int = maxLegsSet
    fun getDrainPct(): Int = drainPct
    fun getSendPct(): Int = sendPct
    fun getMaxOooq(): Int = maxOooq
    fun exitConfluxRatio(): Double = exitConfluxRatio

    /** C Tor `conflux_params_get_*`. */
    fun confluxParamsGetDrainPct(): Int = getDrainPct()
    fun confluxParamsGetMaxLegsSet(): Int = getMaxLegsSet()
    fun confluxParamsGetMaxLinkedSet(): Int = getMaxLinkedSet()
    fun confluxParamsGetMaxOooq(): Int = getMaxOooq()
    fun confluxParamsGetMaxPrebuilt(): Int = getMaxPrebuilt()
    fun confluxParamsGetMaxUnlinkedLegRetry(): Int = getMaxUnlinkedLegRetry()
    fun confluxParamsGetNumLegsSet(): Int = getNumLegsSet()
    fun confluxParamsGetSendPct(): Int = getSendPct()

    /**
     * C Tor `conflux_params_new_consensus` — apply `cfx_*` params and recount exits.
     */
    fun newConsensus(ns: Consensus?) {
        if (ns == null) return
        enabled = ns.param("cfx_enabled", ENABLED_DEFAULT.toLong()).toInt().coerceIn(0, 1) != 0
        maxLinkedSet = ns.param("cfx_max_linked_set", MAX_LINKED_SET_DEFAULT.toLong())
            .toInt().coerceIn(0, 255)
        maxPrebuiltSet = ns.param("cfx_max_prebuilt_set", MAX_PREBUILT_SET_DEFAULT.toLong())
            .toInt().coerceIn(0, 255)
        maxUnlinkedLegRetry = ns.param("cfx_max_unlinked_leg_retry", MAX_UNLINKED_LEG_RETRY_DEFAULT.toLong())
            .toInt().coerceIn(0, 255)
        numLegsSet = ns.param("cfx_num_legs_set", NUM_LEGS_SET_DEFAULT.toLong())
            .toInt().coerceIn(0, 255)
        maxLegsSet = ns.param("cfx_max_legs_set", MAX_LEGS_SET_DEFAULT.toLong())
            .toInt().coerceIn(3, 255)
        sendPct = ns.param("cfx_send_pct", SEND_PCT_DEFAULT.toLong()).toInt().coerceIn(0, 255)
        drainPct = ns.param("cfx_drain_pct", DRAIN_PCT_DEFAULT.toLong()).toInt().coerceIn(0, 255)
        val low = ns.param("cfx_low_exit_threshold", LOW_EXIT_THRESHOLD_DEFAULT.toLong())
            .toInt().coerceIn(0, 10_000)
        lowExitThresholdRatio = low / 10_000.0
        maxOooq = ns.param("cfx_max_oooq_bytes", MAX_OOO_QUEUE_BYTES_DEFAULT.toLong())
            .toInt().coerceAtLeast(0)
        countExitWithConfluxSupport(ns)
    }

    /** C Tor `conflux_params_new_consensus` alias. */
    fun confluxParamsNewConsensus(ns: Consensus?) = newConsensus(ns)

    /** Test/helper: set exit support ratio without a full consensus. */
    fun setExitConfluxRatioForTests(ratio: Double) {
        exitConfluxRatio = ratio.coerceIn(0.0, 1.0)
    }

    private fun countExitWithConfluxSupport(ns: Consensus) {
        var supported = 0.0
        var total = 0
        for (rs in ns.relays) {
            if (!rs.isExit || rs.isBadExit) continue
            total++
            if (rs.supportsConflux) supported++
        }
        exitConfluxRatio = if (total > 0) supported / total else 0.0
    }

    @Suppress("UNUSED_PARAMETER")
    fun warnIfRelayDisabled(config: TorConfig) {
        if (config.runtime.confluxEnabled == false && RouterMode.serverMode(config)) {
            // C Tor hourly ratelim warn — logged by caller if desired.
        }
    }
}
