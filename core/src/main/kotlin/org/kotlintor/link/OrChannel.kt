package org.kotlintor.link

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import java.util.ArrayDeque

/**
 * Channel state (C Tor `channel_state_t`).
 */
enum class ChannelState {
    OPENING,
    OPEN,
    CLOSING,
    CLOSED,
    ERROR,
}

/**
 * Scheduler view of a channel (C Tor `SCHED_CHAN_*`).
 */
enum class ChannelSchedState {
    IDLE,
    WAITING_FOR_CELLS,
    WAITING_TO_WRITE,
    PENDING,
}

/**
 * Channel outbuf / inbuf accounting (C Tor `channel_t` + `connection_t` buffers).
 *
 * Cells destined for the TLS socket accumulate in [outbuf] until the write
 * scheduler drains them; inbound bytes land in [inbuf] before cell decode.
 */
class OrChannel(
    val globalId: Long = nextGid.getAndIncrement(),
    var state: ChannelState = ChannelState.OPENING,
    var remoteAddr: String = "",
    var remotePort: Int = 0,
) {
    private val outq = ArrayDeque<ByteArray>()
    private val inq = ArrayDeque<ByteArray>()
    var outbufBytes: Long = 0
        private set
    var inbufBytes: Long = 0
        private set
    var cellsQueued: Int = 0
        private set
    var cellsWritten: Long = 0
        private set
    var cellsRead: Long = 0
        private set
    var bytesWritten: Long = 0
        private set
    var bytesRead: Long = 0
        private set
    var schedState: ChannelSchedState = ChannelSchedState.IDLE
    var hasBeenOpen: Boolean = false
    var paddingEnabled: Boolean = true
    /** Associated OR connection table handle id. */
    var orConnId: Long? = null
    /** RSA identity digest hex (C Tor channel identity map). */
    var identityDigestHex: String? = null
    /** True when this side initiated the OR connection (client). */
    var isClient: Boolean = true
    /** Ed25519 identity (C Tor alleged id on OR conn). */
    var ed25519Identity: ByteArray? = null
    /** Canonical ORPort peer (C Tor `is_canonical`). */
    var canonical: Boolean = false
    /** Optional inbound cell dispatch hook (C Tor `channel_get_cell_handler`). */
    var cellHandler: ((ByteArray) -> Unit)? = null

    fun markOpen() {
        state = ChannelState.OPEN
        hasBeenOpen = true
        updateSched()
    }

    fun markClosing() {
        state = ChannelState.CLOSING
    }

    fun markClosed() {
        state = ChannelState.CLOSED
        clearOutbuf()
        clearInbuf()
        schedState = ChannelSchedState.IDLE
    }

    /** Queue an encoded cell (or fragment) onto the outbuf. */
    fun queueOut(data: ByteArray): Boolean {
        if (state == ChannelState.CLOSED || state == ChannelState.ERROR) return false
        if (outbufBytes + data.size > MAX_OUTBUF) return false
        outq.addLast(data.copyOf())
        outbufBytes += data.size.toLong()
        cellsQueued++
        updateSched()
        return true
    }

    /** Pop next outbuf chunk for TLS write; null if empty. */
    fun popOut(): ByteArray? {
        val d = (if (outq.isEmpty()) null else outq.removeFirst()) ?: return null
        outbufBytes = (outbufBytes - d.size.toLong()).coerceAtLeast(0)
        cellsQueued = (cellsQueued - 1).coerceAtLeast(0)
        cellsWritten++
        bytesWritten += d.size.toLong()
        updateSched()
        return d
    }

    fun peekOutSize(): Int = outq.firstOrNull()?.size ?: 0

    fun clearOutbuf() {
        outq.clear()
        outbufBytes = 0
        cellsQueued = 0
        updateSched()
    }

    fun appendIn(data: ByteArray) {
        inq.addLast(data.copyOf())
        inbufBytes += data.size.toLong()
        bytesRead += data.size.toLong()
    }

    fun popIn(): ByteArray? {
        val d = (if (inq.isEmpty()) null else inq.removeFirst()) ?: return null
        inbufBytes = (inbufBytes - d.size.toLong()).coerceAtLeast(0)
        cellsRead++
        return d
    }

    fun clearInbuf() {
        inq.clear()
        inbufBytes = 0
    }

    fun noteCellRead() {
        cellsRead++
    }

    /** Direct write accounting (Vanilla path — no lingering outbuf entry). */
    fun bytesWrittenAccount(n: Int) {
        if (n <= 0) return
        cellsWritten++
        bytesWritten += n.toLong()
    }

    private fun updateSched() {
        schedState = when {
            state != ChannelState.OPEN -> ChannelSchedState.IDLE
            cellsQueued > 0 && outbufBytes > 0 -> ChannelSchedState.PENDING
            cellsQueued == 0 -> ChannelSchedState.WAITING_FOR_CELLS
            else -> ChannelSchedState.WAITING_TO_WRITE
        }
    }

    companion object {
        private val nextGid = AtomicLong(1)
        const val MAX_OUTBUF: Long = 32L * 1024 * 1024

        fun resetGidForTests() {
            nextGid.set(1)
        }
    }
}

/** Global channel map (C Tor channel gidmap + identity digest map). */
object ChannelTable {
    private val byId = ConcurrentHashMap<Long, OrChannel>()
    private val byIdentity = ConcurrentHashMap<String, OrChannel>()

    fun register(ch: OrChannel): OrChannel {
        byId[ch.globalId] = ch
        return ch
    }

    fun remove(id: Long): OrChannel? {
        val ch = byId.remove(id)
        ch?.identityDigestHex?.let { byIdentity.remove(it.uppercase()) }
        return ch
    }

    fun get(id: Long): OrChannel? = byId[id]

    fun putIdentity(ch: OrChannel) {
        val id = ch.identityDigestHex?.uppercase() ?: return
        byIdentity[id] = ch
    }

    fun removeByIdentity(ch: OrChannel) {
        ch.identityDigestHex?.uppercase()?.let { byIdentity.remove(it) }
    }

    fun getByIdentity(identityHex: String): OrChannel? =
        byIdentity[identityHex.uppercase()]

    fun count(): Int = byId.size

    fun openCount(): Int = byId.values.count { it.state == ChannelState.OPEN }

    fun clear() {
        byId.clear()
        byIdentity.clear()
    }
}

/**
 * Create and link an entry (AP) connection with an exit edge for same-process
 * accounting (C Tor linked AP↔EXIT pair).
 */
object EdgeLinkedPair {
    data class Pair(
        val entry: EntryConnectionHandle,
        val exit: ExitConnectionHandle,
    )

    fun open(
        clientHost: String,
        clientPort: Int,
        destHost: String,
        destPort: Int,
        circId: Long,
        streamId: Int,
        socksUser: String? = null,
        isolationKey: String? = null,
    ): Pair {
        val entry = ConnectionTable.newEntry(clientHost, clientPort, socksUser, isolationKey)
        entry.originalDest = "$destHost:$destPort"
        entry.markOpen()
        val exit = ConnectionTable.newExit(destHost, destPort, streamId, circId)
        exit.markOpen()
        entry.linkTo(exit)
        return Pair(entry, exit)
    }

    fun close(pair: Pair) {
        pair.entry.markClosed()
        pair.exit.markClosed()
        ConnectionTable.remove(pair.entry.id)
        ConnectionTable.remove(pair.exit.id)
    }
}
