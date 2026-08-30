package org.kotlintor.control

import java.util.concurrent.atomic.AtomicBoolean

/**
 * ORCONN bootstrap-event bridge (C Tor `btrack_orconn.c`).
 *
 * Inventory: `L1:feature/control/btrack_orconn.c`
 *
 * Emission: [org.kotlintor.control.OrconnEvent].
 */
object BtrackOrconn {
    private val initialized = AtomicBoolean(false)
    private val pubsub = AtomicBoolean(false)

    @Volatile private var bestAnyGid: Long = 0
    @Volatile private var bestAnyState: Int = -1
    @Volatile private var bestApGid: Long = 0
    @Volatile private var bestApState: Int = -1

    fun emitLaunched(connId: Long, target: String) =
        OrconnEvent.emitLaunched(connId, target)

    fun emitConnected(connId: Long, target: String) =
        OrconnEvent.emitConnected(connId, target)

    fun emitFailed(connId: Long, reason: String) =
        OrconnEvent.emitFailed(connId, reason)

    fun emitClosed(connId: Long, reason: String = "") =
        OrconnEvent.emitClosed(connId, reason)

    /** C Tor `btrack_orconn_init`. */
    fun btrackOrconnInit(): Int {
        BtrackOrconnMaps.btoInitMaps()
        resetBests()
        initialized.set(true)
        return 0
    }

    /** C Tor `btrack_orconn_fini`. */
    fun btrackOrconnFini() {
        BtrackOrconnMaps.btoClearMaps()
        resetBests()
        BtrackOrconnCevent.btoCeventReset()
        initialized.set(false)
        pubsub.set(false)
    }

    /** C Tor `btrack_orconn_add_pubsub`. */
    fun btrackOrconnAddPubsub(): Int {
        pubsub.set(true)
        return 0
    }

    fun isInitialized(): Boolean = initialized.get()

    fun hasPubsub(): Boolean = pubsub.get()

    fun bestAny(): Pair<Long, Int> = bestAnyGid to bestAnyState

    fun bestAp(): Pair<Long, Int> = bestApGid to bestApState

    /** Update best-any / best-ap caches (C Tor `bto_update_bests` subset). */
    fun noteOrconn(bto: BtOrconn) {
        if (bto.state >= bestAnyState) {
            bestAnyGid = bto.gid
            if (bto.state > bestAnyState) bestAnyState = bto.state
        }
        if (bto.isOrig && !bto.isOnehop && bto.state >= bestApState) {
            bestApGid = bto.gid
            if (bto.state > bestApState) bestApState = bto.state
        }
        BtrackOrconnCevent.btoCeventAnyconn(bto)
        if (bto.isOrig && !bto.isOnehop) {
            BtrackOrconnCevent.btoCeventApconn(bto)
        }
    }

    private fun resetBests() {
        bestAnyGid = 0
        bestAnyState = -1
        bestApGid = 0
        bestApState = -1
    }
}
