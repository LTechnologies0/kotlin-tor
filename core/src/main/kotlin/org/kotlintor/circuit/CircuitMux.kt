package org.kotlintor.circuit

import java.util.concurrent.ConcurrentHashMap
import kotlin.math.pow

/**
 * Typed outbound cell queue (C Tor `cell_queue_t`).
 */
class CellQueue(private val maxCells: Int = DEFAULT_MAX) {
    private val q = ArrayDeque<ByteArray>()

    fun append(payload: ByteArray): Boolean {
        if (q.size >= maxCells) return false
        q.addLast(payload.copyOf())
        totalAllocationBytes.addAndGet(payload.size.toLong())
        return true
    }

    fun pop(): ByteArray? {
        if (q.isEmpty()) return null
        val p = q.removeFirst()
        totalAllocationBytes.addAndGet(-p.size.toLong())
        return p
    }

    fun peek(): ByteArray? = q.firstOrNull()

    fun clear() {
        while (q.isNotEmpty()) {
            val p = q.removeFirst()
            totalAllocationBytes.addAndGet(-p.size.toLong())
        }
    }

    fun size(): Int = q.size
    fun isEmpty(): Boolean = q.isEmpty()

    companion object {
        const val DEFAULT_MAX: Int = 1024

        private val totalAllocationBytes = java.util.concurrent.atomic.AtomicLong(0)

        /** C Tor `cell_queue_init`. */
        fun cellQueueInit(maxCells: Int = DEFAULT_MAX): CellQueue = CellQueue(maxCells)

        /** C Tor `cell_queue_append`. */
        fun cellQueueAppend(queue: CellQueue, payload: ByteArray): Boolean = queue.append(payload)

        /** C Tor `cell_queue_append_packed_copy` (copy into queue). */
        fun cellQueueAppendPackedCopy(queue: CellQueue, payload: ByteArray): Boolean =
            queue.append(payload)

        /** C Tor `cell_queue_clear`. */
        fun cellQueueClear(queue: CellQueue) = queue.clear()

        /** C Tor `cell_queue_pop`. */
        fun cellQueuePop(queue: CellQueue): ByteArray? = queue.pop()

        /** C Tor `cell_queues_check_size` — true if under soft cap. */
        fun cellQueuesCheckSize(softCapBytes: Long = 64L * 1024 * 1024): Boolean =
            totalAllocationBytes.get() <= softCapBytes

        /** C Tor `cell_queues_get_total_allocation`. */
        fun cellQueuesGetTotalAllocation(): Long = totalAllocationBytes.get().coerceAtLeast(0)

        fun resetTotalAllocationForTests() {
            totalAllocationBytes.set(0)
        }
    }
}

/**
 * Destroy-cell queue (C Tor `destroy_cell_queue_t`).
 */
class DestroyCellQueue {
    data class Entry(val circId: Long, val reason: Int)

    private val q = ArrayDeque<Entry>()

    fun append(circId: Long, reason: Int = 0) {
        q.addLast(Entry(circId, reason))
    }

    fun pop(): Entry? = if (q.isEmpty()) null else q.removeFirst()
    fun size(): Int = q.size
    fun isEmpty(): Boolean = q.isEmpty()
    fun clear() = q.clear()

    /** C Tor `destroy_cell_queue_append`. */
    fun destroyCellQueueAppend(circId: Long, reason: Int = 0) = append(circId, reason)
}

/**
 * Circuit multiplexer (C Tor `circuitmux_t` / `circuitmux.c`).
 *
 * Selects which attached circuit should transmit next under a pluggable policy
 * (default: [EwmaCircuitMuxPolicy]). Each circuit carries a [CellQueue]; channel
 * DESTROY cells use [destroyQueue].
 */
class CircuitMux(
    private var policy: CircuitMuxPolicy = EwmaCircuitMuxPolicy(),
    private val maxCellsPerCirc: Int = CellQueue.DEFAULT_MAX,
) {
    private val circuits = ConcurrentHashMap<Long, MuxCircuit>()
    val destroyQueue = DestroyCellQueue()

    data class MuxCircuit(
        val id: Long,
        var active: Boolean = false,
        var queuedCells: Int = 0,
        var policyData: Any? = null,
        val cellQueue: CellQueue = CellQueue(),
    )

    fun setPolicy(p: CircuitMuxPolicy) {
        policy = p
    }

    fun policy(): CircuitMuxPolicy = policy

    fun attach(circId: Long, initialCells: Int = 0) {
        val mc = MuxCircuit(
            id = circId,
            active = initialCells > 0,
            queuedCells = initialCells,
            cellQueue = CellQueue(maxCellsPerCirc),
        )
        mc.policyData = policy.allocCircData(mc)
        circuits[circId] = mc
        if (mc.active) policy.notifyActive(mc)
    }

    fun detach(circId: Long) {
        val mc = circuits.remove(circId) ?: return
        policy.notifyInactive(mc)
        policy.freeCircData(mc)
        mc.cellQueue.clear()
    }

    /** Enqueue an encoded cell payload for [circId]; updates active/EWMA counts. */
    fun enqueue(circId: Long, payload: ByteArray): Boolean {
        val mc = circuits[circId] ?: return false
        if (!mc.cellQueue.append(payload)) return false
        setQueuedCells(circId, mc.cellQueue.size())
        return true
    }

    fun dequeue(circId: Long): ByteArray? {
        val mc = circuits[circId] ?: return null
        val p = mc.cellQueue.pop() ?: return null
        setQueuedCells(circId, mc.cellQueue.size())
        return p
    }

    fun setQueuedCells(circId: Long, n: Int) {
        val mc = circuits[circId] ?: return
        val was = mc.active
        mc.queuedCells = n.coerceAtLeast(0)
        mc.active = mc.queuedCells > 0
        when {
            !was && mc.active -> policy.notifyActive(mc)
            was && !mc.active -> policy.notifyInactive(mc)
            mc.active -> policy.notifySetNCells(mc)
        }
    }

    fun notifyXmit(circId: Long, nCells: Int) {
        val mc = circuits[circId] ?: return
        policy.notifyXmit(mc, nCells)
        setQueuedCells(circId, (mc.queuedCells - nCells).coerceAtLeast(0))
    }

    fun queueDestroy(circId: Long, reason: Int = 0) {
        destroyQueue.append(circId, reason)
    }

    /** Prefer destroy cells, else policy pick among active circuits. */
    fun pickActive(): Long? {
        if (!destroyQueue.isEmpty()) {
            return destroyQueue.pop()?.circId
        }
        return policy.pickActive(circuits.values.filter { it.active })
    }

    fun numCircuits(): Int = circuits.size
    fun numActive(): Int = circuits.values.count { it.active }
    fun numCells(): Int = circuits.values.sumOf { it.queuedCells } + destroyQueue.size()
    fun isAttached(circId: Long): Boolean = circuits.containsKey(circId)
    fun isActive(circId: Long): Boolean = circuits[circId]?.active == true
    fun circuitQueueSize(circId: Long): Int = circuits[circId]?.cellQueue?.size() ?: 0

    /** C Tor `circuitmux_detach_all_circuits` / `channel_unlink_all_circuits`. */
    fun detachAll() {
        circuits.keys.toList().forEach { detach(it) }
        destroyQueue.clear()
    }

    /** C Tor `circuitmux_free_`. */
    fun free() = detachAll()

    /** C Tor `circuitmux_assert_okay` — lightweight invariant check. */
    fun assertOkay(): Boolean =
        circuits.values.all { it.queuedCells == it.cellQueue.size() && it.active == (it.queuedCells > 0) }

    /** C Tor `circuitmux_clear_num_cells`. */
    fun clearNumCells(circId: Long) = setQueuedCells(circId, 0)

    /** C Tor `circuitmux_clear_policy` — restore default EWMA. */
    fun clearPolicy() {
        policy = EwmaCircuitMuxPolicy()
    }

    /** C Tor `circuitmux_count_queued_destroy_cells`. */
    fun countQueuedDestroyCells(): Int = destroyQueue.size()

    /** C Tor `circuitmux_get_first_active_circuit`. */
    fun getFirstActiveCircuit(): Long? = policy.pickActive(circuits.values.filter { it.active })

    /** C Tor `circuitmux_mark_destroyed_circids_usable` (no-op until reuse map). */
    fun markDestroyedCircidsUsable() = Unit

    /** C Tor `circuitmux_notify_xmit_cells`. */
    fun notifyXmitCells(circId: Long, nCells: Int) = notifyXmit(circId, nCells)

    /** C Tor `circuitmux_notify_xmit_destroy`. */
    fun notifyXmitDestroy() {
        if (!destroyQueue.isEmpty()) destroyQueue.pop()
    }

    /** C Tor `circuitmux_num_active_circuits`. */
    fun numActiveCircuits(): Int = numActive()

    /** C Tor `circuitmux_num_cells_for_circuit`. */
    fun numCellsForCircuit(circId: Long): Int = circuitQueueSize(circId)

    /** C Tor `circuitmux_set_num_cells`. */
    fun setNumCells(circId: Long, n: Int) = setQueuedCells(circId, n)

    /** C Tor `circuitmux_attached_circuit_direction` — 0 outbound / 1 inbound stub. */
    fun attachedCircuitDirection(circId: Long): Int = if (isAttached(circId)) 0 else -1

    /** C Tor `append_cell_to_circuit_queue`. */
    fun appendCellToCircuitQueue(circId: Long, payload: ByteArray): Boolean = enqueue(circId, payload)

    /** C Tor `circuit_clear_cell_queue`. */
    fun circuitClearCellQueue(circId: Long) {
        val mc = circuits[circId] ?: return
        mc.cellQueue.clear()
        setQueuedCells(circId, 0)
    }

    companion object {
        /** C Tor `circuitmux_alloc`. */
        fun circuitmuxAlloc(policy: CircuitMuxPolicy = EwmaCircuitMuxPolicy()): CircuitMux =
            CircuitMux(policy)

        /** C Tor `channel_unlink_all_circuits`. */
        fun channelUnlinkAllCircuits(mux: CircuitMux) = mux.detachAll()
    }

    /** C Tor `circuitmux_set_policy`. */
    fun circuitmuxSetPolicy(p: CircuitMuxPolicy) = setPolicy(p)

    /** C Tor `circuitmux_is_circuit_active`. */
    fun circuitmuxIsCircuitActive(circId: Long): Boolean = isActive(circId)

    /** C Tor `circuitmux_is_circuit_attached`. */
    fun circuitmuxIsCircuitAttached(circId: Long): Boolean = isAttached(circId)

    /** C Tor `circuitmux_num_circuits`. */
    fun circuitmuxNumCircuits(): Int = numCircuits()

    /** C Tor `circuitmux_append_destroy_cell`. */
    fun circuitmuxAppendDestroyCell(circId: Long, reason: Int = 0) = queueDestroy(circId, reason)

    /**
     * Drain one unit of work for the channel writer (C Tor cmux flush path).
     * Prefers DESTROY entries, else the EWMA-picked circuit's next queued cell.
     */
    sealed class FlushItem {
        data class Destroy(val circId: Long, val reason: Int) : FlushItem()
        data class Cell(val circId: Long, val payload: ByteArray) : FlushItem()
    }

    fun flushNext(): FlushItem? {
        if (!destroyQueue.isEmpty()) {
            val e = destroyQueue.pop() ?: return null
            return FlushItem.Destroy(e.circId, e.reason)
        }
        val id = policy.pickActive(circuits.values.filter { it.active }) ?: return null
        val mc = circuits[id] ?: return null
        val payload = mc.cellQueue.pop() ?: return null
        setQueuedCells(id, mc.cellQueue.size())
        policy.notifyXmit(mc, 1)
        return FlushItem.Cell(id, payload)
    }

    /** Flush up to [maxItems] queued cells/destroys. */
    fun flush(maxItems: Int = 32): List<FlushItem> {
        val out = ArrayList<FlushItem>(maxItems.coerceAtMost(32))
        repeat(maxItems) {
            out += flushNext() ?: return out
        }
        return out
    }

    /**
     * Fair multi-circuit drain: round-robin across active circuits after DESTROYs,
     * capped by [maxItems] (C Tor cmux under multi-OR load).
     */
    fun flushFair(maxItems: Int = 32): List<FlushItem> {
        val out = ArrayList<FlushItem>(maxItems.coerceAtMost(32))
        while (out.size < maxItems && !destroyQueue.isEmpty()) {
            val e = destroyQueue.pop() ?: break
            out += FlushItem.Destroy(e.circId, e.reason)
        }
        val activeIds = circuits.values.filter { it.active }.map { it.id }.sorted()
        if (activeIds.isEmpty()) return out
        var idx = 0
        var idleRounds = 0
        while (out.size < maxItems && idleRounds < activeIds.size) {
            val id = activeIds[idx % activeIds.size]
            idx++
            val mc = circuits[id]
            if (mc == null || !mc.active) {
                idleRounds++
                continue
            }
            val payload = mc.cellQueue.pop()
            if (payload == null) {
                idleRounds++
                continue
            }
            idleRounds = 0
            setQueuedCells(id, mc.cellQueue.size())
            policy.notifyXmit(mc, 1)
            out += FlushItem.Cell(id, payload)
        }
        return out
    }
}

interface CircuitMuxPolicy {
    fun allocCircData(mc: CircuitMux.MuxCircuit): Any? = null
    fun freeCircData(mc: CircuitMux.MuxCircuit) = Unit
    fun notifyActive(mc: CircuitMux.MuxCircuit) = Unit
    fun notifyInactive(mc: CircuitMux.MuxCircuit) = Unit
    fun notifySetNCells(mc: CircuitMux.MuxCircuit) = Unit
    fun notifyXmit(mc: CircuitMux.MuxCircuit, nCells: Int) = Unit
    fun pickActive(active: Collection<CircuitMux.MuxCircuit>): Long?
}

/**
 * EWMA cell-count policy (C Tor `circuitmux_ewma.c`).
 *
 * Prefer circuits that have been quieter recently. Cell weight decays by
 * `scaleFactor` each tick of [tickLenSec].
 */
class EwmaCircuitMuxPolicy(
    var tickLenSec: Int = EWMA_TICK_LEN_DEFAULT,
    halfLifeSec: Double = EWMA_DEFAULT_HALFLIFE,
) : CircuitMuxPolicy {
    data class CircEwma(var cellCount: Double = 0.0, var lastTick: Int = 0)

    private var activeTick: Int = currentTick()
    private var scaleFactor: Double = computeScale(halfLifeSec)
    var halfLifeSec: Double = halfLifeSec
        private set

    fun setHalfLife(halfLifeSec: Double) {
        this.halfLifeSec = halfLifeSec
        scaleFactor = computeScale(halfLifeSec, tickLenSec)
    }

    /** Apply consensus/config: `CircuitPriorityHalflifeMsec` (C Tor). */
    fun applyConsensusParams(params: Map<String, Long>) {
        val msec = params["CircuitPriorityHalflifeMsec"]
        if (msec != null) {
            setHalfLife(msec / 1000.0)
            return
        }
        val sec = params["CircuitPriorityHalflife"]
        if (sec != null) setHalfLife(sec.toDouble())
    }

    override fun allocCircData(mc: CircuitMux.MuxCircuit): Any = CircEwma(lastTick = activeTick)

    override fun notifyXmit(mc: CircuitMux.MuxCircuit, nCells: Int) {
        val e = mc.policyData as? CircEwma ?: return
        rescale(e)
        e.cellCount += nCells
    }

    override fun pickActive(active: Collection<CircuitMux.MuxCircuit>): Long? {
        if (active.isEmpty()) return null
        if (scaleFactor <= 0.0 || scaleFactor >= 1.0 - EPSILON) {
            return active.minWith(compareBy({ it.queuedCells }, { it.id }))?.id
        }
        return active.minByOrNull { mc ->
            val e = mc.policyData as? CircEwma ?: CircEwma()
            rescale(e)
            e.cellCount
        }?.id
    }

    private fun rescale(e: CircEwma) {
        val now = currentTick()
        if (now != activeTick) activeTick = now
        if (e.lastTick != now && scaleFactor > 0 && scaleFactor < 1.0) {
            val ticks = (now - e.lastTick).coerceAtLeast(0)
            e.cellCount *= scaleFactor.pow(ticks.toDouble())
            e.lastTick = now
        }
    }

    private fun currentTick(): Int =
        (System.currentTimeMillis() / 1000 / tickLenSec.coerceAtLeast(1)).toInt()

    companion object {
        const val EWMA_TICK_LEN_DEFAULT: Int = 10
        const val EWMA_DEFAULT_HALFLIFE: Double = 0.0
        const val EWMA_DEFAULT_HALFLIFE_MSEC: Long = 30_000
        private const val EPSILON: Double = 0.00001
        private const val LOG_ONEHALF: Double = -0.69314718055994529

        fun computeScale(halfLifeSec: Double, tickLen: Int = EWMA_TICK_LEN_DEFAULT): Double {
            if (halfLifeSec < EPSILON) return 0.0
            val ticks = halfLifeSec / tickLen.coerceAtLeast(1)
            return kotlin.math.exp(LOG_ONEHALF / ticks)
        }

        fun fromConsensus(params: Map<String, Long>): EwmaCircuitMuxPolicy {
            val p = EwmaCircuitMuxPolicy(halfLifeSec = EWMA_DEFAULT_HALFLIFE_MSEC / 1000.0)
            p.applyConsensusParams(params)
            return p
        }
    }
}

/**
 * Half-closed edge stream (C Tor `half_edge_t`).
 *
 * Tracks streams we closed locally while the other end may still send DATA/SENDME.
 */
data class HalfEdge(
    val streamId: Int,
    var sendmesPending: Int = 0,
    var dataPending: Int = 0,
    var endAckExpectedUsec: Long = 0,
    var usedCcontrol: Boolean = false,
    var connectedPending: Boolean = false,
)

class HalfEdgeSet {
    private val byId = ConcurrentHashMap<Int, HalfEdge>()

    fun add(edge: HalfEdge) {
        byId[edge.streamId] = edge
    }

    fun remove(streamId: Int): HalfEdge? = byId.remove(streamId)

    fun get(streamId: Int): HalfEdge? = byId[streamId]

    fun contains(streamId: Int): Boolean = byId.containsKey(streamId)

    fun expireDue(nowUsec: Long = System.nanoTime() / 1000): List<HalfEdge> {
        val gone = byId.values.filter { e ->
            e.usedCcontrol && e.endAckExpectedUsec > 0 && nowUsec >= e.endAckExpectedUsec
        }
        gone.forEach { byId.remove(it.streamId) }
        return gone
    }

    /** True if inbound DATA/SENDME for this stream should still be accepted. */
    fun acceptInbound(streamId: Int, isSendme: Boolean, isData: Boolean): Boolean {
        val e = byId[streamId] ?: return false
        if (isSendme) {
            if (e.sendmesPending <= 0) return false
            e.sendmesPending--
            if (e.sendmesPending == 0 && e.dataPending <= 0 && !e.connectedPending) {
                byId.remove(streamId)
            }
            return true
        }
        if (isData) {
            if (e.dataPending <= 0 && !e.usedCcontrol) return false
            if (!e.usedCcontrol) e.dataPending--
            if (e.sendmesPending <= 0 && e.dataPending <= 0 && !e.connectedPending) {
                byId.remove(streamId)
            }
            return true
        }
        return true
    }

    val size: Int get() = byId.size
}
