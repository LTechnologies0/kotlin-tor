package org.kotlintor

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * C Tor control-spec `STATUS_CLIENT BOOTSTRAP` phases.
 * [tag] is the default STATUS line; [advance] may override SUMMARY for more detail.
 */
enum class BootstrapPhase(val tagName: String, val progress: Int, val defaultSummary: String) {
    STARTING("starting", 0, "Starting"),
    CONN_DIR("conn_dir", 5, "Connecting to directory server"),
    HANDSHAKE_DIR("handshake_dir", 10, "Finishing handshake with directory server"),
    REQUESTING_STATUS("requesting_status", 15, "Fetching consensus"),
    LOADING_STATUS("loading_status", 20, "Loading consensus"),
    LOADING_KEYS("loading_keys", 40, "Loading authority certificates"),
    REQUESTING_DESCRIPTORS("requesting_descriptors", 45, "Fetching descriptors"),
    LOADING_DESCRIPTORS("loading_descriptors", 50, "Loading descriptors"),
    CONN_OR("conn_or", 80, "Connecting to the Tor network"),
    HANDSHAKE_OR("handshake_or", 85, "Finishing handshake with first hop"),
    CIRCUIT_CREATE("circuit_create", 90, "Establishing a Tor circuit"),
    DONE("done", 100, "Done"),
    ;

    fun statusLine(summary: String = defaultSummary): String =
        "NOTICE BOOTSTRAP PROGRESS=$progress TAG=$tagName SUMMARY=\"${escapeSummary(summary)}\""

    /** Legacy field used by older call sites expecting a full STATUS line. */
    val tag: String get() = statusLine()

    companion object {
        fun escapeSummary(s: String): String =
            s.replace('\\', '/').replace('"', '\'')
    }
}

class BootstrapTracker(
    private val onAdvance: ((String) -> Unit)? = null,
) {
    private val _phase = MutableStateFlow(BootstrapPhase.STARTING)
    val phase: StateFlow<BootstrapPhase> = _phase.asStateFlow()

    /**
     * Advance to [to] if it is not behind the current progress.
     * Always notifies [onAdvance] when the phase actually changes (or [forceNotify]).
     */
    fun advance(
        to: BootstrapPhase,
        summary: String? = null,
        forceNotify: Boolean = false,
    ) {
        val changed = to.progress >= _phase.value.progress && to != _phase.value
        if (to.progress >= _phase.value.progress) {
            _phase.value = to
        }
        if (changed || forceNotify) {
            val line = to.statusLine(summary ?: to.defaultSummary)
            onAdvance?.invoke(line)
        }
    }

    /** Emit the current phase again (e.g. daemon start). */
    fun notifyCurrent(summary: String? = null) {
        val p = _phase.value
        onAdvance?.invoke(p.statusLine(summary ?: p.defaultSummary))
    }

    val statusLine: String get() = _phase.value.statusLine()
}
