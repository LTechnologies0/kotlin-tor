package org.kotlintor.link

import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Connection type tree (C Tor `connection_t` / `connection_st` hierarchy).
 *
 * Sockets remain the carrier; this models typed handles for accounting,
 * listeners, linked pairs, and channel association.
 */
enum class ConnectionType {
    OR,
    EXIT,
    AP, // application (SOCKS/HTTP) — entry_connection_t
    DIR,
    CONTROL,
    LISTENER,
    EXT_OR,
}

enum class ConnectionState {
    CONNECTING,
    HANDSHAKING,
    OPEN,
    CLOSING,
    CLOSED,
}

open class Connection(
    val id: Long,
    val type: ConnectionType,
    val address: String,
    val port: Int,
    var state: ConnectionState = ConnectionState.CONNECTING,
) {
    var bytesRead: Long = 0
    var bytesWritten: Long = 0
    var createdAtMs: Long = System.currentTimeMillis()
    /** C Tor linked_conn: pair id when two conns share a pipe (e.g. AP↔EXIT). */
    var linkedConnId: Long? = null
    var linked: Boolean = false
    var readBlockedOnBw: Boolean = false
    var writeBlockedOnBw: Boolean = false
    var holdOpenUntilFlushed: Boolean = false

    fun noteRead(n: Long) {
        bytesRead += n.coerceAtLeast(0)
    }

    fun noteWritten(n: Long) {
        bytesWritten += n.coerceAtLeast(0)
    }

    fun markOpen() {
        state = ConnectionState.OPEN
    }

    fun markHandshaking() {
        state = ConnectionState.HANDSHAKING
    }

    fun markClosing() {
        state = ConnectionState.CLOSING
    }

    fun markClosed() {
        state = ConnectionState.CLOSED
    }

    fun linkTo(other: Connection) {
        linked = true
        linkedConnId = other.id
        other.linked = true
        other.linkedConnId = id
    }
}

class OrConnectionHandle(
    id: Long,
    address: String,
    port: Int,
    val isClient: Boolean,
    var circMuxAttached: Boolean = false,
    var channelId: Long? = null,
    var identityFpHex: String? = null,
) : Connection(id, ConnectionType.OR, address, port)

class ExitConnectionHandle(
    id: Long,
    address: String,
    port: Int,
    val streamId: Int,
    val circId: Long,
) : Connection(id, ConnectionType.EXIT, address, port)

/** Application / SOCKS entry connection (C Tor `entry_connection_t`). */
class EntryConnectionHandle(
    id: Long,
    address: String,
    port: Int,
    val socksUser: String? = null,
    val isolationKey: String? = null,
    var originalDest: String? = null,
) : Connection(id, ConnectionType.AP, address, port)

/** @deprecated Use [EntryConnectionHandle]; kept for call-site compatibility. */
typealias ApConnectionHandle = EntryConnectionHandle

class DirConnectionHandle(
    id: Long,
    address: String,
    port: Int,
    val purpose: String = "fetch",
    var resource: String? = null,
) : Connection(id, ConnectionType.DIR, address, port)

class ControlConnectionHandle(
    id: Long,
    address: String,
    port: Int,
    var authenticated: Boolean = false,
) : Connection(id, ConnectionType.CONTROL, address, port)

class ExtOrConnectionHandle(
    id: Long,
    address: String,
    port: Int,
    var transportName: String? = null,
    var userId: String? = null,
) : Connection(id, ConnectionType.EXT_OR, address, port)

class ListenerConnection(
    id: Long,
    bindHost: String,
    bindPort: Int,
    val listenType: ConnectionType,
) : Connection(id, ConnectionType.LISTENER, bindHost, bindPort)

/** Safe downcasts (C Tor `TO_OR_CONN` / `TO_EDGE_CONN` lite). */
object ConnectionCast {
    fun toOr(c: Connection?): OrConnectionHandle? = c as? OrConnectionHandle
    fun toExit(c: Connection?): ExitConnectionHandle? = c as? ExitConnectionHandle
    fun toEntry(c: Connection?): EntryConnectionHandle? = c as? EntryConnectionHandle
    fun toDir(c: Connection?): DirConnectionHandle? = c as? DirConnectionHandle
    fun toControl(c: Connection?): ControlConnectionHandle? = c as? ControlConnectionHandle
    fun toExtOr(c: Connection?): ExtOrConnectionHandle? = c as? ExtOrConnectionHandle
    fun toListener(c: Connection?): ListenerConnection? = c as? ListenerConnection
}

/**
 * Global connection table (C Tor `connection_array` lite).
 */
object ConnectionTable {
    private val nextId = AtomicLong(1)
    private val byId = ConcurrentHashMap<Long, Connection>()

    fun allocId(): Long = nextId.getAndIncrement()

    fun add(conn: Connection): Connection {
        byId[conn.id] = conn
        return conn
    }

    fun remove(id: Long): Connection? = byId.remove(id)

    fun get(id: Long): Connection? = byId[id]

    fun byType(type: ConnectionType): List<Connection> =
        byId.values.filter { it.type == type }

    fun countOpen(): Int = byId.values.count { it.state == ConnectionState.OPEN }

    fun count(): Int = byId.size

    fun all(): Collection<Connection> = byId.values

    fun clear() = byId.clear()

    fun linkedPeer(conn: Connection): Connection? =
        conn.linkedConnId?.let { byId[it] }

    fun newOr(host: String, port: Int, isClient: Boolean): OrConnectionHandle =
        add(OrConnectionHandle(allocId(), host, port, isClient)) as OrConnectionHandle

    fun newAp(peer: InetAddress, port: Int, socksUser: String? = null): EntryConnectionHandle =
        newEntry(peer.hostAddress ?: "0.0.0.0", port, socksUser)

    fun newEntry(
        host: String,
        port: Int,
        socksUser: String? = null,
        isolationKey: String? = null,
    ): EntryConnectionHandle =
        add(EntryConnectionHandle(allocId(), host, port, socksUser, isolationKey)) as EntryConnectionHandle

    fun newExit(host: String, port: Int, streamId: Int, circId: Long): ExitConnectionHandle =
        add(ExitConnectionHandle(allocId(), host, port, streamId, circId)) as ExitConnectionHandle

    fun newDir(host: String, port: Int, purpose: String = "fetch"): DirConnectionHandle =
        add(DirConnectionHandle(allocId(), host, port, purpose)) as DirConnectionHandle

    fun newControl(host: String, port: Int): ControlConnectionHandle =
        add(ControlConnectionHandle(allocId(), host, port)) as ControlConnectionHandle

    fun newExtOr(host: String, port: Int): ExtOrConnectionHandle =
        add(ExtOrConnectionHandle(allocId(), host, port)) as ExtOrConnectionHandle

    fun newListener(host: String, port: Int, listenType: ConnectionType): ListenerConnection =
        add(ListenerConnection(allocId(), host, port, listenType)) as ListenerConnection
}
