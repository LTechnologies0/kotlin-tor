package org.kotlintor.pt

import java.util.concurrent.CopyOnWriteArrayList

/**
 * Pluggable transport registry (C Tor `transports.c` / `transports.h`).
 *
 * Inventory: `L1:feature/client/transports.c`
 */
object Transports {
    private val names = linkedSetOf<String>()
    private val marked = linkedSetOf<String>()
    private val proxies = CopyOnWriteArrayList<ManagedProxy>()
    private var ptProxyUri: String? = null
    private val lastErrors = CopyOnWriteArrayList<String>()
    private val lastLogs = CopyOnWriteArrayList<String>()
    private val lastStatus = CopyOnWriteArrayList<String>()

    fun clear() {
        names.clear()
        marked.clear()
        proxies.clear()
        ptProxyUri = null
        lastErrors.clear()
        lastLogs.clear()
        lastStatus.clear()
    }

    fun register(name: String): Boolean = names.add(name.lowercase())

    fun unregister(name: String): Boolean = names.remove(name.lowercase())

    fun isRegistered(name: String): Boolean = name.lowercase() in names

    fun list(): List<String> = names.toList()

    fun count(): Int = names.size

    /** C Tor `mark_transport_list`. */
    fun markTransportList() {
        marked.clear()
        marked.addAll(names)
    }

    /** C Tor `managed_proxy_create`. */
    fun managedProxyCreate(
        transports: List<String>,
        argv: List<String>,
        isServer: Boolean = false,
    ): ManagedProxy {
        val mp = ManagedProxy(
            transports = transports.map { it.lowercase() }.toMutableList(),
            argv = argv.toMutableList(),
            isServer = isServer,
            state = PtProtoState.INFANT,
        )
        proxies += mp
        for (t in mp.transports) register(t)
        return mp
    }

    /** C Tor `managed_proxy_destroy`. */
    fun managedProxyDestroy(mp: ManagedProxy): ManagedProxy? {
        proxies.remove(mp)
        return null
    }

    /** C Tor `managed_proxy_has_transport`. */
    fun managedProxyHasTransport(transportName: String): Boolean {
        val n = transportName.lowercase()
        return proxies.any { n in it.transports } || isRegistered(n)
    }

    /** C Tor `managed_proxy_set_state` / `managed_proxy_state_to_string`. */
    fun managedProxySetState(mp: ManagedProxy, newState: PtProtoState) {
        mp.state = newState
    }

    fun managedProxyStateToString(state: PtProtoState): String = state.name.lowercase()

    /** C Tor `managed_proxy_severity_parse` — PT LOG severity → level int. */
    fun managedProxySeverityParse(severity: String): Int? =
        when (severity.trim().lowercase()) {
            "debug" -> 7
            "info" -> 6
            "notice" -> 5
            "warn", "warning" -> 4
            "error", "err" -> 3
            else -> null
        }

    /** C Tor `managed_proxy_outbound_address`. */
    fun managedProxyOutboundAddress(family: Int = 4): String =
        if (family == 6) "::1" else "127.0.0.1"

    /** C Tor `configure_proxy` — mark configured when argv present. */
    fun configureProxy(mp: ManagedProxy): Int {
        if (mp.argv.isEmpty()) return -1
        managedProxySetState(mp, PtProtoState.LAUNCHED)
        return 1
    }

    /** C Tor `launch_proxy_ev` — record launch intent (no OS process in unit tests). */
    fun launchProxyEv(mp: ManagedProxy): Boolean {
        if (mp.state == PtProtoState.INFANT) configureProxy(mp)
        managedProxySetState(mp, PtProtoState.LAUNCHED)
        return true
    }

    /** C Tor `get_pt_proxy_uri`. */
    fun getPtProxyUri(): String? = ptProxyUri

    fun setPtProxyUri(uri: String?) {
        ptProxyUri = uri
    }

    /** C Tor `get_transport_proxy_ports` — socks ports from CMETHOD lines. */
    fun getTransportProxyPorts(): List<Int> =
        proxies.flatMap { it.cmethods.map { m -> m.port } }.distinct()

    /** C Tor `get_transport_options_for_server_proxy`. */
    fun getTransportOptionsForServerProxy(mp: ManagedProxy): String =
        mp.smethods.joinToString(",") { it.name }

    /** C Tor `free_execve_args`. */
    fun freeExecveArgs(args: MutableList<String>?): MutableList<String>? {
        args?.clear()
        return null
    }

    /** C Tor `handle_proxy_line` — dispatch PT stdout protocol lines. */
    fun handleProxyLine(line: String, mp: ManagedProxy) {
        val t = line.trim()
        when {
            t.startsWith("CMETHOD ") -> parseCmethodLine(t, mp)
            t.startsWith("SMETHOD ") -> parseSmethodLine(t, mp)
            t.startsWith("ENV-ERROR ") -> parseEnvError(t)
            t.startsWith("PROXY-ERROR ") -> parseProxyError(t)
            t.startsWith("LOG ") -> parseLogLine(t, mp)
            t.startsWith("STATUS ") -> parseStatusLine(t, mp)
            t.startsWith("VERSION ") -> {
                managedProxySetState(mp, PtProtoState.CONFIGURING)
            }
            t == "CMETHODS DONE" || t == "SMETHODS DONE" ->
                managedProxySetState(mp, PtProtoState.COMPLETED)
        }
    }

    /** C Tor `parse_cmethod_line` — `CMETHOD <transport> socks5 <addr:port>`. */
    fun parseCmethodLine(line: String, mp: ManagedProxy): Int {
        val parts = line.trim().split(Regex("\\s+"))
        if (parts.size < 4 || parts[0] != "CMETHOD") return -1
        val name = parts[1].lowercase()
        val proto = parts[2].lowercase()
        val hostPort = parts[3]
        val colon = hostPort.lastIndexOf(':')
        if (colon <= 0) return -1
        val port = hostPort.substring(colon + 1).toIntOrNull() ?: return -1
        val host = hostPort.substring(0, colon)
        mp.cmethods += PtMethod(name, proto, host, port)
        register(name)
        if (name !in mp.transports) mp.transports += name
        return 0
    }

    /** C Tor `parse_smethod_line`. */
    fun parseSmethodLine(line: String, mp: ManagedProxy): Int {
        val parts = line.trim().split(Regex("\\s+"))
        if (parts.size < 3 || parts[0] != "SMETHOD") return -1
        val name = parts[1].lowercase()
        val hostPort = parts[2]
        val colon = hostPort.lastIndexOf(':')
        if (colon <= 0) return -1
        val port = hostPort.substring(colon + 1).toIntOrNull() ?: return -1
        val host = hostPort.substring(0, colon)
        mp.smethods += PtMethod(name, "server", host, port)
        register(name)
        return 0
    }

    /** C Tor `parse_env_error`. */
    fun parseEnvError(line: String) {
        lastErrors += line.trim()
    }

    /** C Tor `parse_proxy_error`. */
    fun parseProxyError(line: String) {
        lastErrors += line.trim()
    }

    /** C Tor `parse_log_line`. */
    fun parseLogLine(line: String, mp: ManagedProxy) {
        lastLogs += line.trim()
        mp.lastLog = line.trim()
    }

    /** C Tor `parse_status_line`. */
    fun parseStatusLine(line: String, mp: ManagedProxy) {
        lastStatus += line.trim()
        mp.lastStatus = line.trim()
    }

    /** C Tor `handle_status_message`. */
    fun handleStatusMessage(values: Map<String, String>): String {
        val msg = values.entries.joinToString(" ") { "${it.key}=${it.value}" }
        lastStatus += msg
        return msg
    }

    /** C Tor `managed_proxy_stdout_callback`. */
    fun managedProxyStdoutCallback(mp: ManagedProxy, line: String) {
        handleProxyLine(line, mp)
    }

    /** C Tor `managed_proxy_stderr_callback`. */
    fun managedProxyStderrCallback(mp: ManagedProxy, line: String) {
        parseLogLine("LOG SEVERE $line", mp)
    }

    /** C Tor `managed_proxy_exit_callback`. */
    fun managedProxyExitCallback(mp: ManagedProxy, exitCode: Int): Boolean {
        managedProxySetState(mp, if (exitCode == 0) PtProtoState.COMPLETED else PtProtoState.BROKEN)
        return exitCode == 0
    }

    fun proxies(): List<ManagedProxy> = proxies.toList()
    fun lastErrors(): List<String> = lastErrors.toList()
    fun lastLogs(): List<String> = lastLogs.toList()
    fun lastStatus(): List<String> = lastStatus.toList()
}

/** C Tor `pt_proto_state`. */
enum class PtProtoState {
    INFANT,
    LAUNCHED,
    CONFIGURING,
    COMPLETED,
    BROKEN,
}

/** C Tor `managed_proxy_t` subset. */
data class ManagedProxy(
    val transports: MutableList<String>,
    val argv: MutableList<String>,
    val isServer: Boolean,
    var state: PtProtoState,
    val cmethods: MutableList<PtMethod> = mutableListOf(),
    val smethods: MutableList<PtMethod> = mutableListOf(),
    var lastLog: String? = null,
    var lastStatus: String? = null,
)

data class PtMethod(
    val name: String,
    val protocol: String,
    val host: String,
    val port: Int,
)
