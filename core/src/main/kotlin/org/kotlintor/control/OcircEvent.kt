package org.kotlintor.control

import java.util.concurrent.CopyOnWriteArrayList

/**
 * OR circuit status events (C Tor `ocirc_event.c`).
 *
 * Inventory: `L1:core/or/ocirc_event.c`
 */
object OcircEvent {
    enum class Status {
        LAUNCHED,
        BUILT,
        EXTENDED,
        FAILED,
        CLOSED,
    }

    data class Event(
        val circId: Long,
        val status: Status,
        val path: String = "",
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

    fun emitLaunched(circId: Long) = emit(Event(circId, Status.LAUNCHED))

    fun emitBuilt(circId: Long, path: String = "") =
        emit(Event(circId, Status.BUILT, path = path))

    fun emitFailed(circId: Long, reason: String) =
        emit(Event(circId, Status.FAILED, reason = reason))

    fun emitClosed(circId: Long, reason: String = "") =
        emit(Event(circId, Status.CLOSED, reason = reason))

    /** C Tor `ocirc_cevent_publish`. */
    fun ocircCeventPublish(circId: Long, status: Status, path: String = "", reason: String = "") {
        emit(Event(circId, status, path, reason))
    }

    /** C Tor `ocirc_chan_publish` — channel association note. */
    fun ocircChanPublish(circId: Long, chanGid: Long) {
        emit(Event(circId, Status.EXTENDED, path = "chan=$chanGid"))
    }

    /** C Tor `ocirc_state_publish`. */
    fun ocircStatePublish(circId: Long, status: Status) {
        emit(Event(circId, status))
    }

    /** Control-port CIRC event line fragment. */
    fun formatControl(ev: Event): String {
        val base = "650 CIRC ${ev.circId} ${ev.status.name}"
        return when {
            ev.path.isNotEmpty() -> "$base ${ev.path}"
            ev.reason.isNotEmpty() -> "$base REASON=${ev.reason}"
            else -> base
        }
    }
}
