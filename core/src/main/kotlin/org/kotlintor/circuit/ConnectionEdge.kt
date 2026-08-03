package org.kotlintor.circuit

import org.kotlintor.cell.Reasons
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Edge-connection / stream table (C Tor `connection_edge.c` lite).
 *
 * Tracks application and exit stream state keyed by circuit+stream id.
 */
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
