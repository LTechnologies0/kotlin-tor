package org.kotlintor.control

import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

/**
 * ORCONN control-event formatting (C Tor `btrack_orconn_cevent.c`).
 *
 * Inventory: `L1:feature/control/btrack_orconn_cevent.c`
 */
object BtrackOrconnCevent {
    private val firstOrconnDone = AtomicBoolean(false)
    private val bootstrapListeners = CopyOnWriteArrayList<(Int) -> Unit>()

    /** Last bootstrap status code emitted by [btoCeventAnyconn]/[btoCeventApconn]. */
    @Volatile
    var lastBootstrapStatus: Int = -1
        private set

    fun format(status: String, target: String): String =
        ControlFmt.orconnEvent(status, target)

    fun launched(target: String): String = format("LAUNCHED", target)

    fun connected(target: String): String = format("CONNECTED", target)

    fun failed(target: String): String = format("FAILED", target)

    fun closed(target: String): String = format("CLOSED", target)

    fun addBootstrapListener(listener: (Int) -> Unit) {
        bootstrapListeners += listener
    }

    fun clearBootstrapListeners() {
        bootstrapListeners.clear()
    }

    fun hasCompletedFirstOrconn(): Boolean = firstOrconnDone.get()

    /** C Tor `bto_cevent_reset`. */
    fun btoCeventReset() {
        firstOrconnDone.set(false)
        lastBootstrapStatus = -1
    }

    /**
     * C Tor `bto_cevent_anyconn` — decode ORCONN state into bootstrap STATUS codes.
     * Returns the emitted status, or null when no event applies.
     */
    fun btoCeventAnyconn(bto: BtOrconn): Int? {
        val status = when (bto.state) {
            BtOrconn.STATE_CONNECTING -> when {
                usingPt(bto) -> BOOTSTRAP_CONN_PT
                usingProxy(bto) -> BOOTSTRAP_CONN_PROXY
                else -> BOOTSTRAP_CONN
            }
            BtOrconn.STATE_PROXY_HANDSHAKING -> when {
                usingPt(bto) -> BOOTSTRAP_CONN_DONE_PT
                usingProxy(bto) -> BOOTSTRAP_CONN_DONE_PROXY
                else -> null
            }
            BtOrconn.STATE_TLS_HANDSHAKING -> BOOTSTRAP_CONN_DONE
            BtOrconn.STATE_OR_HANDSHAKING_V3 -> BOOTSTRAP_HANDSHAKE
            BtOrconn.STATE_OPEN -> {
                firstOrconnDone.set(true)
                BOOTSTRAP_HANDSHAKE_DONE
            }
            else -> null
        }
        if (status != null) emitBootstrap(status)
        return status
    }

    /**
     * C Tor `bto_cevent_apconn` — application-circuit ORCONN progress after first ORCONN.
     */
    fun btoCeventApconn(bto: BtOrconn): Int? {
        if (!firstOrconnDone.get()) return null
        val status = when (bto.state) {
            BtOrconn.STATE_CONNECTING -> when {
                usingPt(bto) -> BOOTSTRAP_AP_CONN_PT
                usingProxy(bto) -> BOOTSTRAP_AP_CONN_PROXY
                else -> BOOTSTRAP_AP_CONN
            }
            BtOrconn.STATE_PROXY_HANDSHAKING -> when {
                usingPt(bto) -> BOOTSTRAP_AP_CONN_DONE_PT
                usingProxy(bto) -> BOOTSTRAP_AP_CONN_DONE_PROXY
                else -> null
            }
            BtOrconn.STATE_TLS_HANDSHAKING -> BOOTSTRAP_AP_CONN_DONE
            BtOrconn.STATE_OR_HANDSHAKING_V3 -> BOOTSTRAP_AP_HANDSHAKE
            BtOrconn.STATE_OPEN -> BOOTSTRAP_AP_HANDSHAKE_DONE
            else -> null
        }
        if (status != null) emitBootstrap(status)
        return status
    }

    private fun emitBootstrap(status: Int) {
        lastBootstrapStatus = status
        for (l in bootstrapListeners) l(status)
    }

    private fun usingPt(bto: BtOrconn): Boolean = bto.proxyType == BtOrconn.PROXY_PLUGGABLE

    private fun usingProxy(bto: BtOrconn): Boolean =
        when (bto.proxyType) {
            BtOrconn.PROXY_CONNECT,
            BtOrconn.PROXY_SOCKS4,
            BtOrconn.PROXY_SOCKS5,
            BtOrconn.PROXY_HAPROXY,
            -> true
            else -> false
        }

    // C Tor bootstrap_status_t (control_events.h) — subset used by bto_cevent_*.
    const val BOOTSTRAP_CONN_PT = 1
    const val BOOTSTRAP_CONN_DONE_PT = 2
    const val BOOTSTRAP_CONN_PROXY = 3
    const val BOOTSTRAP_CONN_DONE_PROXY = 4
    const val BOOTSTRAP_CONN = 5
    const val BOOTSTRAP_CONN_DONE = 10
    const val BOOTSTRAP_HANDSHAKE = 14
    const val BOOTSTRAP_HANDSHAKE_DONE = 15
    const val BOOTSTRAP_AP_CONN_PT = 76
    const val BOOTSTRAP_AP_CONN_DONE_PT = 77
    const val BOOTSTRAP_AP_CONN_PROXY = 78
    const val BOOTSTRAP_AP_CONN_DONE_PROXY = 79
    const val BOOTSTRAP_AP_CONN = 80
    const val BOOTSTRAP_AP_CONN_DONE = 85
    const val BOOTSTRAP_AP_HANDSHAKE = 89
    const val BOOTSTRAP_AP_HANDSHAKE_DONE = 90
}
