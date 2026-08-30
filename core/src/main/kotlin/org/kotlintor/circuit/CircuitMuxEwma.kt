package org.kotlintor.circuit

/**
 * EWMA circuitmux policy (C Tor `circuitmux_ewma.c`).
 *
 * Inventory: `L1:core/or/circuitmux_ewma.c`
 *
 * Implementation lives in [EwmaCircuitMuxPolicy]; this object is the naming-
 * aligned entry surface.
 */
object CircuitMuxEwma {
    const val TICK_LEN_DEFAULT: Int = EwmaCircuitMuxPolicy.EWMA_TICK_LEN_DEFAULT
    const val DEFAULT_HALFLIFE_MSEC: Long = EwmaCircuitMuxPolicy.EWMA_DEFAULT_HALFLIFE_MSEC

    @Volatile private var ticksInitialized: Boolean = false
    @Volatile private var tickEpochMs: Long = 0

    fun newPolicy(
        tickLenSec: Int = TICK_LEN_DEFAULT,
        halfLifeSec: Double = DEFAULT_HALFLIFE_MSEC / 1000.0,
    ): EwmaCircuitMuxPolicy = EwmaCircuitMuxPolicy(tickLenSec, halfLifeSec)

    fun fromConsensus(params: Map<String, Long>): EwmaCircuitMuxPolicy =
        EwmaCircuitMuxPolicy.fromConsensus(params)

    fun computeScale(halfLifeSec: Double, tickLen: Int = TICK_LEN_DEFAULT): Double =
        EwmaCircuitMuxPolicy.computeScale(halfLifeSec, tickLen)

    /** C Tor `cell_ewma_initialize_ticks`. */
    fun cellEwmaInitializeTicks(nowMs: Long = System.currentTimeMillis()) {
        tickEpochMs = nowMs
        ticksInitialized = true
    }

    /**
     * C Tor `cell_ewma_get_current_tick_and_fraction`.
     * @return tick index to [TICK_LEN_DEFAULT] seconds, plus fraction into the tick.
     */
    fun cellEwmaGetCurrentTickAndFraction(
        nowMs: Long = System.currentTimeMillis(),
        tickLenSec: Int = TICK_LEN_DEFAULT,
    ): Pair<Int, Double> {
        if (!ticksInitialized) cellEwmaInitializeTicks(nowMs)
        val lenMs = tickLenSec.coerceAtLeast(1) * 1000L
        val elapsed = (nowMs - tickEpochMs).coerceAtLeast(0)
        val tick = (elapsed / lenMs).toInt()
        val frac = (elapsed % lenMs).toDouble() / lenMs.toDouble()
        return tick to frac
    }

    /** C Tor `circuitmux_ewma_free_all`. */
    fun circuitmuxEwmaFreeAll() {
        ticksInitialized = false
        tickEpochMs = 0
    }

    /** C Tor `cmux_ewma_set_options`. */
    fun cmuxEwmaSetOptions(policy: EwmaCircuitMuxPolicy, halfLifeMsec: Long) {
        policy.setHalfLife(halfLifeMsec / 1000.0)
    }
}
