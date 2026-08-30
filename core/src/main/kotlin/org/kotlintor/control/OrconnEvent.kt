package org.kotlintor.control

import java.util.concurrent.CopyOnWriteArrayList

/**
 * OR connection status events (C Tor `orconn_event.c`).
 *
 * Inventory: `L1:core/or/orconn_event.c`
 */
object OrconnEvent {
    enum class Status {
        LAUNCHED,
        CONNECTED,
        FAILED,
        CLOSED,
    }

    data class Event(
        val connId: Long,
        val status: Status,
        val target: String = "",
        val reason: String = "",
    )

    private val listeners = CopyOnWriteArrayList<(Event) -> Unit>()

    fun addListener(l: (Event) -> Unit) {
        listeners += l
    }

    fun removeListener(l: (Event) -> Unit) {
        listeners -= l
    }

    fun clearListeners() = listeners.clear()

    fun emit(ev: Event) {
        for (l in listeners) l(ev)
    }

    fun emitLaunched(connId: Long, target: String) =
        emit(Event(connId, Status.LAUNCHED, target = target))

    fun emitConnected(connId: Long, target: String) =
        emit(Event(connId, Status.CONNECTED, target = target))

    fun emitFailed(connId: Long, reason: String) =
        emit(Event(connId, Status.FAILED, reason = reason))

    fun emitClosed(connId: Long, reason: String = "") =
        emit(Event(connId, Status.CLOSED, reason = reason))

    /** C Tor `orconn_state_publish`. */
    fun orconnStatePublish(connId: Long, status: Status, target: String = "") {
        emit(Event(connId, status, target = target))
    }

    /** C Tor `orconn_status_publish`. */
    fun orconnStatusPublish(connId: Long, status: Status, target: String = "", reason: String = "") {
        emit(Event(connId, status, target = target, reason = reason))
    }

    /** Control-port ORCONN event line fragment. */
    fun formatControl(ev: Event): String {
        val base = "650 ORCONN ${ev.target.ifEmpty { ev.connId.toString() }} ${ev.status.name}"
        return if (ev.reason.isNotEmpty()) "$base REASON=${ev.reason}" else base
    }
}
