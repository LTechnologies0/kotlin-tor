package org.kotlintor.control

import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Control event subscription names + emitters (C Tor `control_events.c`).
 *
 * Inventory: `L1:feature/control/control_events.c`
 *
 * Circ/ORCONN status emission: [org.kotlintor.control.OcircEvent], [org.kotlintor.control.OrconnEvent].
 */
object ControlEvents {
    val KNOWN: Set<String> = setOf(
        "CIRC",
        "STREAM",
        "ORCONN",
        "BW",
        "DEBUG",
        "INFO",
        "NOTICE",
        "WARN",
        "ERR",
        "NEWDESC",
        "ADDRMAP",
        "AUTHDIR_NEWDESCS",
        "DESCCHANGED",
        "STATUS_GENERAL",
        "STATUS_CLIENT",
        "STATUS_SERVER",
        "GUARD",
        "NS",
        "STREAM_BW",
        "CLIENTS_SEEN",
        "NEWCONSENSUS",
        "BUILDTIMEOUT_SET",
        "SIGNAL",
        "CONF_CHANGED",
        "CONN_BW",
        "CELL_STATS",
        "TB_EMPTY",
        "CIRC_BW",
        "TRANSPORT_LAUNCHED",
        "HS_DESC",
        "HS_DESC_CONTENT",
        "NETWORK_LIVENESS",
    )

    private val listeners = CopyOnWriteArrayList<(String) -> Unit>()
    private val perSecondEnabled = AtomicBoolean(false)
    private val logSeverity = AtomicInteger(3) // NOTICE-ish
    private val lastBootMsg = AtomicReference("Starting")
    private val bootstrappedOrconn = AtomicBoolean(false)

    fun parseList(spaceSeparated: String): Set<String> =
        spaceSeparated.split(Regex("\\s+"))
            .map { it.trim().uppercase() }
            .filter { it.isNotEmpty() && it in KNOWN }
            .toSet()

    fun isKnown(name: String): Boolean = name.uppercase() in KNOWN

    fun addListener(listener: (String) -> Unit) {
        listeners += listener
    }

    fun clearListeners() {
        listeners.clear()
    }

    private fun emit(line: String) {
        for (l in listeners) l(line)
    }

    /** C Tor `control_adjust_event_log_severity`. */
    fun controlAdjustEventLogSeverity(level: Int = 3) {
        logSeverity.set(level)
    }

    fun eventLogSeverity(): Int = logSeverity.get()

    /** C Tor `control_any_per_second_event_enabled`. */
    fun controlAnyPerSecondEventEnabled(): Boolean = perSecondEnabled.get()

    fun setPerSecondEventsEnabled(enabled: Boolean) {
        perSecondEnabled.set(enabled)
    }

    /** C Tor `append_cell_stats_by_command`. */
    fun appendCellStatsByCommand(
        eventParts: MutableList<String>,
        commandId: Int,
        queued: Int,
        delivered: Int,
    ) {
        eventParts += "Command=$commandId Queued=$queued Delivered=$delivered"
    }

    /** C Tor `cbt_control_event_buildtimeout_set` / `control_event_buildtimeout_set`. */
    fun cbtControlEventBuildtimeoutSet(timeoutMs: Int, totalTimes: Int = 0): String {
        val line = "650 BUILDTIMEOUT_SET COMPUTED TIMEOUT=$timeoutMs TOTAL_TIMES=$totalTimes"
        emit(line)
        return line
    }

    fun controlEventBuildtimeoutSet(timeoutMs: Int, totalTimes: Int = 0): String =
        cbtControlEventBuildtimeoutSet(timeoutMs, totalTimes)

    /** C Tor `control_event_address_mapped`. */
    fun controlEventAddressMapped(from: String, to: String, expires: Long = 0, error: String? = null): String {
        val line =
            if (error != null) "650 ADDRMAP $from $to error=\"$error\""
            else if (expires > 0) "650 ADDRMAP $from $to $expires"
            else "650 ADDRMAP $from $to NEVER"
        emit(line)
        return line
    }

    /** C Tor `control_event_bandwidth_used`. */
    fun controlEventBandwidthUsed(nRead: Long, nWritten: Long): String {
        val line = "650 BW $nRead $nWritten"
        emit(line)
        return line
    }

    /** C Tor `control_event_bootstrap`. */
    fun controlEventBootstrap(status: Int, progress: Int): String {
        val line = "650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=$progress TAG=status_$status"
        lastBootMsg.set("bootstrap $status/$progress")
        emit(line)
        return line
    }

    /** C Tor `control_event_boot_dir`. */
    fun controlEventBootDir(status: Int, progress: Int): String {
        val line = "650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=$progress TAG=boot_dir_$status"
        lastBootMsg.set("boot_dir $status")
        emit(line)
        return line
    }

    /** C Tor `control_event_boot_first_orconn`. */
    fun controlEventBootFirstOrconn() {
        bootstrappedOrconn.set(true)
        lastBootMsg.set("first_orconn")
        emit("650 STATUS_CLIENT NOTICE BOOTSTRAP TAG=first_orconn")
    }

    /** C Tor `control_event_boot_last_msg`. */
    fun controlEventBootLastMsg(): String = lastBootMsg.get()

    /** C Tor `control_event_bootstrap_problem`. */
    fun controlEventBootstrapProblem(warn: String, reason: String): String {
        val line = "650 STATUS_CLIENT WARN BOOTSTRAP PROBLEM=\"$warn\" REASON=$reason"
        lastBootMsg.set(warn)
        emit(line)
        return line
    }

    /** C Tor `control_event_bootstrap_reset`. */
    fun controlEventBootstrapReset() {
        bootstrappedOrconn.set(false)
        lastBootMsg.set("Starting")
    }

    fun hasFirstOrconn(): Boolean = bootstrappedOrconn.get()

    /** C Tor `rend_auth_type_to_string`. */
    fun rendAuthTypeToString(authType: Int): String =
        when (authType) {
            REND_NO_AUTH -> "NO_AUTH"
            REND_V3_AUTH -> "REND_V3_AUTH"
            else -> "UNKNOWN"
        }

    const val REND_NO_AUTH: Int = 0
    const val REND_V3_AUTH: Int = 1

    /** C Tor `control_event_circ_bandwidth_used`. */
    fun controlEventCircBandwidthUsed(): String {
        val line = "650 CIRC_BW"
        emit(line)
        return line
    }

    /** C Tor `control_event_circ_bandwidth_used_for_circ`. */
    fun controlEventCircBandwidthUsedForCirc(
        circId: Long,
        read: Long,
        written: Long,
        deliveredRead: Long = read,
        deliveredWritten: Long = written,
    ): String {
        val line =
            "650 CIRC_BW ID=$circId READ=$read WRITTEN=$written " +
                "DELIVERED_READ=$deliveredRead DELIVERED_WRITTEN=$deliveredWritten"
        emit(line)
        return line
    }

    /** C Tor `control_event_circuit_status`. */
    fun controlEventCircuitStatus(circId: Long, status: String, path: String = ""): String {
        val line = ControlFmt.circEvent(circId, status, path)
        emit(line)
        return line
    }

    /** C Tor `control_event_circuit_purpose_changed`. */
    fun controlEventCircuitPurposeChanged(circId: Long, oldPurpose: String, newPurpose: String): String {
        val line = "650 CIRC_MINOR $circId PURPOSE_CHANGED PURPOSE=$newPurpose OLD_PURPOSE=$oldPurpose"
        emit(line)
        return line
    }

    /** C Tor `control_event_circuit_cannibalized`. */
    fun controlEventCircuitCannibalized(circId: Long, oldPurpose: String, newPurpose: String): String {
        val line = "650 CIRC_MINOR $circId CANNIBALIZED PURPOSE=$newPurpose OLD_PURPOSE=$oldPurpose"
        emit(line)
        return line
    }

    /** C Tor `control_event_circuit_cell_stats`. */
    fun controlEventCircuitCellStats(circId: Long, parts: List<String>): String {
        val line = "650 CELL_STATS ID=$circId ${parts.joinToString(" ")}"
        emit(line)
        return line
    }

    /** C Tor `control_event_client_error`. */
    fun controlEventClientError(msg: String): String {
        val line = "650 STATUS_CLIENT ERR $msg"
        emit(line)
        return line
    }

    /** C Tor `control_event_client_status`. */
    fun controlEventClientStatus(severity: String, msg: String): String {
        val line = "650 STATUS_CLIENT $severity $msg"
        emit(line)
        return line
    }

    /** C Tor `control_event_clients_seen`. */
    fun controlEventClientsSeen(controllerStr: String): String {
        val line = "650 CLIENTS_SEEN $controllerStr"
        emit(line)
        return line
    }

    /** C Tor `control_event_conf_changed`. */
    fun controlEventConfChanged(changes: List<Pair<String, String>>): String {
        val body = changes.joinToString(" ") { (k, v) -> "$k=$v" }
        val line = "650 CONF_CHANGED $body"
        emit(line)
        return line
    }

    /** C Tor `control_event_conn_bandwidth`. */
    fun controlEventConnBandwidth(connId: Long, read: Long, written: Long, type: String = "OR"): String {
        val line = "650 CONN_BW ID=$connId TYPE=$type READ=$read WRITTEN=$written"
        emit(line)
        return line
    }

    /** C Tor `control_event_conn_bandwidth_used` — flush pending conn BW (no-op marker). */
    fun controlEventConnBandwidthUsed(): Int = 0
}
