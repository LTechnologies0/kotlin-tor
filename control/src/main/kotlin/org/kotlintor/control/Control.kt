package org.kotlintor.control

import kotlinx.coroutines.CoroutineScope
import org.kotlintor.TorDaemon
import org.kotlintor.config.ListenSpec
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Lightweight control-connection session state (C Tor `control_connection_t` subset).
 */
class ControlConnection(
    val id: Long,
    var authenticated: Boolean = false,
    var closed: Boolean = false,
    var reachedEof: Boolean = false,
    var inbuf: StringBuilder = StringBuilder(),
    var outbuf: StringBuilder = StringBuilder(),
    var localFd: Int = -1,
)

/**
 * Control-port listener entry (C Tor `control.c`).
 *
 * Inventory: `L1:feature/control/control.c`
 *
 * Session I/O lives in [ControlServer].
 */
object Control {
    const val DEFAULT_MAX_CONCURRENT: Int = ControlServer.DEFAULT_MAX_CONCURRENT

    private val nextId = AtomicInteger(1)
    private val connections = ConcurrentHashMap<Long, ControlConnection>()
    private val authenticated = CopyOnWriteArrayList<ControlConnection>()
    private val freed = AtomicBoolean(false)
    private val controlPorts = CopyOnWriteArrayList<String>()

    fun open(daemon: TorDaemon, scope: CoroutineScope, maxConcurrent: Int = DEFAULT_MAX_CONCURRENT): ControlServer =
        ControlServer(daemon, scope, maxConcurrent)

    fun start(server: ControlServer, listen: ListenSpec) {
        server.start(listen)
    }

    fun stop(server: ControlServer) {
        server.stop()
    }

    /** C Tor `control_connection_add_local_fd`. */
    fun controlConnectionAddLocalFd(fd: Int, flags: Int = 0): ControlConnection {
        val c = ControlConnection(id = nextId.getAndIncrement().toLong(), localFd = fd)
        connections[c.id] = c
        freed.set(false)
        return c
    }

    /** C Tor `connection_control_process_inbuf` — pull one CRLF-terminated line if present. */
    fun connectionControlProcessInbuf(conn: ControlConnection): String? {
        val text = conn.inbuf.toString()
        val idx = text.indexOf('\n')
        if (idx < 0) return null
        val line = text.substring(0, idx).trimEnd('\r')
        conn.inbuf.delete(0, idx + 1)
        return line
    }

    /** C Tor `connection_control_finished_flushing`. */
    fun connectionControlFinishedFlushing(conn: ControlConnection): Int {
        conn.outbuf.clear()
        return 0
    }

    /** C Tor `connection_control_reached_eof`. */
    fun connectionControlReachedEof(conn: ControlConnection): Int {
        conn.reachedEof = true
        return 0
    }

    /** C Tor `connection_control_closed`. */
    fun connectionControlClosed(conn: ControlConnection) {
        conn.closed = true
        connections.remove(conn.id)
        authenticated.remove(conn)
    }

    fun markAuthenticated(conn: ControlConnection) {
        conn.authenticated = true
        if (conn !in authenticated) authenticated += conn
    }

    /** C Tor `control_remove_authenticated_connection`. */
    fun controlRemoveAuthenticatedConnection(conn: ControlConnection) {
        conn.authenticated = false
        authenticated.remove(conn)
    }

    fun authenticatedCount(): Int = authenticated.size

    fun setControlPorts(ports: List<String>) {
        controlPorts.clear()
        controlPorts.addAll(ports)
    }

    /**
     * C Tor `control_ports_write_to_file` — write configured ControlPort lines.
     * Returns bytes written, or -1 if [path] is null.
     */
    fun controlPortsWriteToFile(path: Path?): Int {
        if (path == null) return -1
        val body = controlPorts.joinToString("\n") + if (controlPorts.isEmpty()) "" else "\n"
        Files.writeString(path, body)
        return body.length
    }

    /** C Tor `control_free_all`. */
    fun controlFreeAll() {
        connections.clear()
        authenticated.clear()
        controlPorts.clear()
        freed.set(true)
    }

    fun connectionCount(): Int = connections.size

    fun wasFreed(): Boolean = freed.get()

    private val loggingEnabled = AtomicBoolean(true)

    /** C Tor `disable_control_logging`. */
    fun disableControlLogging() {
        loggingEnabled.set(false)
    }

    /** C Tor `enable_control_logging`. */
    fun enableControlLogging() {
        loggingEnabled.set(true)
    }

    fun isControlLoggingEnabled(): Boolean = loggingEnabled.get()

    /**
     * C Tor `entry_connection_describe_status_for_controller`.
     */
    fun entryConnectionDescribeStatusForController(
        streamId: Long,
        target: String,
        status: String = "NEW",
    ): String = "STREAM $streamId $status $target"

    /** C Tor `orconn_target_get_name`. */
    fun orconnTargetGetName(address: String, port: Int): String = "$address:$port"

    /** C Tor `monitor_owning_controller_process` — record pid; returns 0. */
    fun monitorOwningControllerProcess(pid: Long): Int {
        owningControllerPid = pid
        return 0
    }

    @Volatile var owningControllerPid: Long = -1
        private set
}
