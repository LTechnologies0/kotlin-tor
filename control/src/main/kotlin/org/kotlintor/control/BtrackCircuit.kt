package org.kotlintor.control

import java.util.concurrent.atomic.AtomicBoolean

/**
 * Circuit bootstrap-event bridge (C Tor `btrack_circuit.c`).
 *
 * Inventory: `L1:feature/control/btrack_circuit.c`
 *
 * Emission: [org.kotlintor.control.OcircEvent].
 */
object BtrackCircuit {
    private val initialized = AtomicBoolean(false)
    private val pubsub = AtomicBoolean(false)

    @Volatile private var bestAnyStateGid: Long = 0
    @Volatile private var bestAnyStateVal: Int = -1
    @Volatile private var bestApStateGid: Long = 0
    @Volatile private var bestApStateVal: Int = -1

    fun emitLaunched(circId: Long) = OcircEvent.emitLaunched(circId)

    fun emitBuilt(circId: Long, path: String = "") = OcircEvent.emitBuilt(circId, path)

    fun emitFailed(circId: Long, reason: String) = OcircEvent.emitFailed(circId, reason)

    fun emitClosed(circId: Long, reason: String = "") = OcircEvent.emitClosed(circId, reason)

    fun format(id: Long, status: String, path: String = ""): String =
        ControlFmt.circEvent(id, status, path)

    /**
     * C Tor `btrack_circ_init` (declared in `btrack_circuit.h`; resets cached bests).
     */
    fun btrackCircInit(): Int {
        resetBests()
        initialized.set(true)
        return 0
    }

    /** C Tor `btrack_circ_fini`. */
    fun btrackCircFini() {
        resetBests()
        initialized.set(false)
        pubsub.set(false)
    }

    /** C Tor `btrack_circ_add_pubsub` — JVM has no C pubsub connector; marks subscription. */
    fun btrackCircAddPubsub(): Int {
        pubsub.set(true)
        return 0
    }

    fun isInitialized(): Boolean = initialized.get()

    fun hasPubsub(): Boolean = pubsub.get()

    fun bestAnyState(): Pair<Long, Int> = bestAnyStateGid to bestAnyStateVal

    fun bestApState(): Pair<Long, Int> = bestApStateGid to bestApStateVal

    /** Record origin-circuit state progress (subset of C Tor `btc_state_rcvr`). */
    fun noteState(gid: Long, state: Int, onehop: Boolean) {
        if (state > bestAnyStateVal) {
            bestAnyStateGid = gid
            bestAnyStateVal = state
        }
        if (!onehop && state > bestApStateVal) {
            bestApStateGid = gid
            bestApStateVal = state
        }
    }

    private fun resetBests() {
        bestAnyStateGid = 0
        bestAnyStateVal = -1
        bestApStateGid = 0
        bestApStateVal = -1
    }
}
