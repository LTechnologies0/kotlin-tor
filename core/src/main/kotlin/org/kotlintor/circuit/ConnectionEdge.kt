package org.kotlintor.circuit

import org.kotlintor.cell.Reasons
import org.kotlintor.cell.RelayCommand
import org.kotlintor.util.SecureRandomSource
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Edge-connection / stream table (C Tor `connection_edge.c`).
 *
 * Inventory: `L1:core/or/connection_edge.c`
 *
 * Tracks application and exit stream state keyed by circuit+stream id.
 */

/** Naming-aligned entry for inventory / `ConnectionEdge.kt`. */
object ConnectionEdge {
    const val MIN_DNS_TTL: Int = 5 * 60
    const val MAX_DNS_TTL: Int = 60 * 60
    const val FUZZY_DNS_TTL: Int = 4 * 60

    const val END_STREAM_REASON_MISC: Int = 1
    const val END_STREAM_REASON_INTERNAL: Int = 2
    const val END_STREAM_REASON_TORPROTOCOL: Int = 3

    /** Parsed BEGIN / BEGIN_DIR (C Tor `begin_cell_t`). */
    data class BeginCell(
        val streamId: Int,
        val address: String = "",
        val port: Int = 0,
        val flags: Int = 0,
        val isBeginDir: Boolean = false,
    )

    fun newTable(): EdgeConnectionTable = EdgeConnectionTable()

    // --- C Tor `connection_edge.h` op aliases (L3) ---

    /**
     * C Tor `address_is_invalid_destination`.
     * @return true if the hostname has illegal characters (unless [allowNonRfc953]).
     */
    fun addressIsInvalidDestination(
        address: String,
        client: Boolean = true,
        allowNonRfc953: Boolean = false,
    ): Boolean {
        if (allowNonRfc953) return false
        @Suppress("UNUSED_PARAMETER")
        val _client = client
        // IP literals are always valid destinations (C Tor tor_addr_parse path).
        if (address.contains(':')) {
            val compact = address.removePrefix("[").removeSuffix("]")
            if (compact.all { it.isDigit() || it in "abcdefABCDEF:" }) return false
        }
        if (address.matches(Regex("""\d{1,3}(\.\d{1,3}){3}"""))) return false
        for (ch in address) {
            if (!(ch.isLetterOrDigit() || ch == '-' || ch == '.' || ch == '_')) return true
        }
        return false
    }

    /** C Tor `clip_dns_ttl`. */
    fun clipDnsTtl(ttl: Int): Int = if (ttl < MIN_DNS_TTL) MIN_DNS_TTL else MAX_DNS_TTL

    /** C Tor `clip_dns_fuzzy_ttl`. */
    fun clipDnsFuzzyTtl(ttl: Int): Int {
        val clipped = clipDnsTtl(ttl)
        val fuzz = SecureRandomSource.nextInt(1 + 2 * FUZZY_DNS_TTL) - FUZZY_DNS_TTL
        return clipped + fuzz
    }

    /**
     * C Tor `begin_cell_parse`.
     * @return Pair(parsed cell or null, end_reason); null cell ⇒ reject.
     */
    fun beginCellParse(
        streamId: Int,
        command: RelayCommand,
        body: ByteArray,
    ): Pair<BeginCell?, Int> {
        if (command == RelayCommand.BEGIN_DIR) {
            return BeginCell(streamId = streamId, isBeginDir = true) to 0
        }
        if (command != RelayCommand.BEGIN) {
            return null to END_STREAM_REASON_INTERNAL
        }
        val nul = body.indexOf(0)
        if (nul < 0) return null to END_STREAM_REASON_TORPROTOCOL
        val addrPort = body.copyOfRange(0, nul).toString(Charsets.UTF_8)
        val colon = addrPort.lastIndexOf(':')
        if (colon <= 0) return null to END_STREAM_REASON_TORPROTOCOL
        val address = addrPort.substring(0, colon)
        val port = addrPort.substring(colon + 1).toIntOrNull() ?: return null to END_STREAM_REASON_TORPROTOCOL
        if (port == 0) return null to END_STREAM_REASON_TORPROTOCOL
        var flags = 0
        if (body.size > nul + 4) {
            flags = ((body[nul + 1].toInt() and 0xff) shl 24) or
                ((body[nul + 2].toInt() and 0xff) shl 16) or
                ((body[nul + 3].toInt() and 0xff) shl 8) or
                (body[nul + 4].toInt() and 0xff)
        }
        return BeginCell(streamId, address, port, flags, false) to 0
    }

    /** C Tor `connected_cell_format_payload`. */
    fun connectedCellFormatPayload(addr: InetAddress, ttl: Int = MAX_DNS_TTL): ByteArray {
        val buf = ByteArray(22)
        val n = Relay.appendAddressToPayload(buf, 0, addr)
        require(n > 0)
        val out = buf.copyOf(n + 4)
        val t = clipDnsTtl(ttl)
        out[n] = ((t ushr 24) and 0xff).toByte()
        out[n + 1] = ((t ushr 16) and 0xff).toByte()
        out[n + 2] = ((t ushr 8) and 0xff).toByte()
        out[n + 3] = (t and 0xff).toByte()
        return out
    }

    /** C Tor `circuit_clear_isolation` (stream isolation tags cleared). */
    fun circuitClearIsolation(table: EdgeConnectionTable, circId: Long) {
        table.streamsOnCircuit(circId) // touch; isolation map not yet separate
    }

    /** C Tor `circuit_discard_optional_exit_enclaves` (no-op until enclaves). */
    fun circuitDiscardOptionalExitEnclaves() = Unit

    /** Application-side stream pending attachment (C Tor `entry_connection_t` subset). */
    enum class ApPending { NONE, PENDING_CIRCUIT, WAITING_RENDDESC }

    data class ApStream(
        val id: Long,
        var target: String = "",
        var port: Int = 0,
        var pending: ApPending = ApPending.NONE,
        var onehopFailed: Boolean = false,
        var socksReplySent: Boolean = false,
        var resolvedAddr: String? = null,
        var beginningExpireAtMs: Long = 0,
        var closed: Boolean = false,
    )

    private val apPending = ConcurrentHashMap<Long, ApStream>()
    private val nextApId = AtomicInteger(1)

    fun connectionApMakeLink(target: String, port: Int = 80): ApStream {
        val s = ApStream(id = nextApId.getAndIncrement().toLong(), target = target, port = port)
        apPending[s.id] = s
        connectionApMarkAsPendingCircuit(s)
        return s
    }

    /** C Tor `connection_ap_about_to_close`. */
    fun connectionApAboutToClose(stream: ApStream) {
        stream.closed = true
        stream.pending = ApPending.NONE
        apPending.remove(stream.id)
    }

    /** C Tor `connection_ap_attach_pending`. */
    fun connectionApAttachPending(): Int {
        var n = 0
        for (s in apPending.values) {
            if (s.pending == ApPending.PENDING_CIRCUIT) {
                s.pending = ApPending.NONE
                n++
            }
        }
        return n
    }

    /** C Tor `connection_ap_rescan_and_attach_pending`. */
    fun connectionApRescanAndAttachPending(): Int = connectionApAttachPending()

    /** C Tor `connection_ap_can_use_exit`. */
    fun connectionApCanUseExit(exitAllows: Boolean): Boolean = exitAllows

    /** C Tor `connection_ap_detach_retriable`. */
    fun connectionApDetachRetriable(stream: ApStream): Boolean {
        if (stream.closed) return false
        connectionApMarkAsPendingCircuit(stream)
        return true
    }

    /** C Tor `connection_ap_expire_beginning`. */
    fun connectionApExpireBeginning(nowMs: Long = System.currentTimeMillis()): Int {
        var n = 0
        for (s in apPending.values.toList()) {
            if (s.beginningExpireAtMs > 0 && nowMs >= s.beginningExpireAtMs) {
                connectionApAboutToClose(s)
                n++
            }
        }
        return n
    }

    /** C Tor `connection_ap_fail_onehop`. */
    fun connectionApFailOnehop(stream: ApStream) {
        stream.onehopFailed = true
        connectionApMarkAsNonPendingCircuit(stream)
    }

    /** C Tor `connection_ap_handshake_rewrite`. */
    fun connectionApHandshakeRewrite(host: String): String =
        host.trim().lowercase().removeSuffix(".")

    /** C Tor `connection_ap_handshake_rewrite_and_attach`. */
    fun connectionApHandshakeRewriteAndAttach(stream: ApStream, host: String): String {
        val rewritten = connectionApHandshakeRewrite(host)
        stream.target = rewritten
        connectionApMarkAsPendingCircuit(stream)
        return rewritten
    }

    /** C Tor `connection_ap_handshake_send_resolve`. */
    fun connectionApHandshakeSendResolve(stream: ApStream, hostname: String): ByteArray {
        stream.target = hostname
        stream.pending = ApPending.PENDING_CIRCUIT
        return hostname.toByteArray(Charsets.UTF_8)
    }

    /** C Tor `connection_ap_handshake_socks_reply`. */
    fun connectionApHandshakeSocksReply(stream: ApStream, status: Int = 0): ByteArray {
        stream.socksReplySent = true
        return byteArrayOf(0x05, (status and 0xff).toByte(), 0x00, 0x01, 0, 0, 0, 0, 0, 0)
    }

    /** C Tor `connection_ap_handshake_socks_resolved_addr`. */
    fun connectionApHandshakeSocksResolvedAddr(stream: ApStream, addr: String): ByteArray {
        stream.resolvedAddr = addr
        return connectionApHandshakeSocksReply(stream, status = 0)
    }

    /** C Tor `connection_ap_mark_as_non_pending_circuit`. */
    fun connectionApMarkAsNonPendingCircuit(stream: ApStream) {
        stream.pending = ApPending.NONE
    }

    /** C Tor `connection_ap_mark_as_pending_circuit_`. */
    fun connectionApMarkAsPendingCircuit(stream: ApStream) {
        stream.pending = ApPending.PENDING_CIRCUIT
        if (stream.beginningExpireAtMs == 0L) {
            stream.beginningExpireAtMs = System.currentTimeMillis() + 60_000
        }
    }

    /** Trailing underscore C name alias. */
    fun connectionApMarkAsPendingCircuit_(stream: ApStream) = connectionApMarkAsPendingCircuit(stream)

    /** C Tor `connection_ap_mark_as_waiting_for_renddesc`. */
    fun connectionApMarkAsWaitingForRenddesc(stream: ApStream) {
        stream.pending = ApPending.WAITING_RENDDESC
    }

    /** C Tor `connection_ap_process_http_connect`. */
    fun connectionApProcessHttpConnect(requestLine: String): Pair<String, Int>? {
        val parts = requestLine.trim().split(Regex("\\s+"))
        if (parts.size < 2 || !parts[0].equals("CONNECT", ignoreCase = true)) return null
        val hostPort = parts[1]
        val colon = hostPort.lastIndexOf(':')
        if (colon <= 0) return null
        val host = hostPort.substring(0, colon)
        val port = hostPort.substring(colon + 1).toIntOrNull() ?: return null
        return host to port
    }

    /** C Tor `connection_ap_process_transparent`. */
    fun connectionApProcessTransparent(destHost: String, destPort: Int): ApStream =
        connectionApMakeLink(destHost, destPort)

    fun clearApPendingForTests() = apPending.clear()
}
enum class EdgeStreamState {
    NEW,
    CONNECTING,
    OPEN,
    RESOLVING,
    CLOSING,
    CLOSED,
}

data class EdgeStream(
    val circId: Long,
    val streamId: Int,
    val isExit: Boolean,
    val target: String,
    var state: EdgeStreamState = EdgeStreamState.NEW,
    var endReason: Int = 0,
    var bytesRead: Long = 0,
    var bytesWritten: Long = 0,
)

class EdgeConnectionTable {
    private val byKey = ConcurrentHashMap<Long, EdgeStream>()
    private val nextLocal = AtomicInteger(1)

    private fun key(circId: Long, streamId: Int): Long =
        (circId shl 16) or (streamId.toLong() and 0xffff)

    fun open(
        circId: Long,
        streamId: Int,
        target: String,
        isExit: Boolean,
    ): EdgeStream {
        val s = EdgeStream(circId, streamId, isExit, target, EdgeStreamState.CONNECTING)
        byKey[key(circId, streamId)] = s
        return s
    }

    fun allocStreamId(): Int = nextLocal.getAndIncrement() and 0xffff

    fun get(circId: Long, streamId: Int): EdgeStream? = byKey[key(circId, streamId)]

    fun markOpen(circId: Long, streamId: Int) {
        byKey[key(circId, streamId)]?.state = EdgeStreamState.OPEN
    }

    fun markEnd(circId: Long, streamId: Int, reason: Int = Reasons.STREAM_DONE) {
        byKey[key(circId, streamId)]?.let {
            it.state = EdgeStreamState.CLOSED
            it.endReason = reason
        }
    }

    fun noteBytes(circId: Long, streamId: Int, read: Long = 0, written: Long = 0) {
        byKey[key(circId, streamId)]?.let {
            it.bytesRead += read.coerceAtLeast(0)
            it.bytesWritten += written.coerceAtLeast(0)
        }
    }

    fun remove(circId: Long, streamId: Int): EdgeStream? = byKey.remove(key(circId, streamId))

    fun streamsOnCircuit(circId: Long): List<EdgeStream> =
        byKey.values.filter { it.circId == circId }

    fun closeCircuit(circId: Long, reason: Int = Reasons.STREAM_DESTROY) {
        byKey.entries.removeIf { (_, v) ->
            if (v.circId == circId) {
                v.state = EdgeStreamState.CLOSED
                v.endReason = reason
                true
            } else {
                false
            }
        }
    }

    fun countOpen(): Int = byKey.values.count { it.state == EdgeStreamState.OPEN }

    fun clear() = byKey.clear()
}
