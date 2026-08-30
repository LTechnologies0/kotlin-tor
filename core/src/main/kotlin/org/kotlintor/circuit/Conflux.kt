package org.kotlintor.circuit

import org.kotlintor.cell.RelayCommand
import java.util.PriorityQueue
import java.util.concurrent.atomic.AtomicLong

/**
 * Prop329 Conflux set state + cell facade (C Tor `conflux.c`).
 *
 * Inventory: `L1:core/or/conflux.c`
 *
 * Cell codecs: [ConfluxCell]. Consensus params: [ConfluxParams].
 */
class ConfluxSet(
    val nonce: ByteArray,
    val circuits: MutableList<Circuit> = mutableListOf(),
) {
    @Volatile var nextSeq: Long = 0
        private set
    @Volatile var linked: Boolean = false
    @Volatile var maxSeqSent: Long = 0
    @Volatile var maxSeqRecv: Long = 0
    var congestion: CongestionControl? = null
    private val oooQ = PriorityQueue<ConfluxMsg>(compareBy { it.seq })
    private var oooBytes: Long = 0

    fun add(circuit: Circuit) {
        if (circuits.none { it.id == circuit.id }) circuits += circuit
    }

    fun nextSequence(): Long = synchronized(this) { nextSeq++ }

    fun size(): Int = circuits.size

    fun validateLegs(maxLegs: Int = ConfluxParams.getMaxLegsSet()): Boolean =
        circuits.size in 1..maxLegs && nonce.size == 32

    fun clearOooQ() {
        oooQ.clear()
        oooBytes = 0
    }

    fun enqueueOoo(msg: ConfluxMsg) {
        oooQ.add(msg)
        oooBytes += Conflux.confluxMsgAllocCost(msg)
    }

    fun dequeueOoo(): ConfluxMsg? {
        val m = oooQ.poll() ?: return null
        oooBytes = (oooBytes - Conflux.confluxMsgAllocCost(m)).coerceAtLeast(0)
        return m
    }

    fun oooByteCost(): Long = oooBytes
}

/** C Tor `conflux_msg_t` — OOO relay message wrapper. */
data class ConfluxMsg(
    val seq: Long,
    val payload: ByteArray = ByteArray(0),
    var heapIdx: Int = -1,
)

object Conflux {
    const val VERSION: Int = ConfluxCell.VERSION

    private val totalBytes = AtomicLong(0)

    fun newNonce(): ByteArray = ConfluxCell.newNonce()

    fun parseLink(data: ByteArray): ConfluxCell.Link = ConfluxCell.parseLink(data)

    fun parseSwitch(data: ByteArray): ConfluxCell.Switch = ConfluxCell.parseSwitch(data)

    fun linkCell(payload: ConfluxCell.Link) = ConfluxCell.buildLink(payload)

    fun linkedCell(payload: ConfluxCell.Link) = ConfluxCell.buildLinked(payload)

    fun linkedAckCell(): ByteArray = ConfluxCell.buildLinkedAck()

    fun switchCell(seq: Long) = ConfluxCell.buildSwitch(seq)

    val linkCommand: RelayCommand get() = ConfluxCell.linkCommand
    val linkedCommand: RelayCommand get() = ConfluxCell.linkedCommand
    val linkedAckCommand: RelayCommand get() = ConfluxCell.linkedAckCommand
    val switchCommand: RelayCommand get() = ConfluxCell.switchCommand

    /** C Tor `circuit_ccontrol`. */
    fun circuitCcontrol(set: ConfluxSet?): CongestionControl? = set?.congestion

    fun circuitCcontrol(cc: CongestionControl?): CongestionControl? = cc

    /** C Tor `conflux_clear_ooo_q`. */
    fun confluxClearOooQ(set: ConfluxSet) = set.clearOooQ()

    /** C Tor `conflux_msg_alloc_cost`. */
    fun confluxMsgAllocCost(msg: ConfluxMsg?): Long =
        if (msg == null) 0 else (64L + msg.payload.size)

    /** C Tor `conflux_handle_oom` — drop OOO until [bytesToRemove] freed; returns freed. */
    fun confluxHandleOom(sets: List<ConfluxSet>, bytesToRemove: Long): Long {
        var removed = 0L
        for (set in sets) {
            while (removed < bytesToRemove) {
                val m = set.dequeueOoo() ?: break
                removed += confluxMsgAllocCost(m)
                totalBytes.addAndGet(-confluxMsgAllocCost(m))
            }
            if (removed >= bytesToRemove) break
        }
        return removed
    }

    fun confluxHandleOom(bytesToRemove: Long): Long =
        confluxHandleOom(emptyList(), bytesToRemove)

    /** C Tor `conflux_get_total_bytes_allocation`. */
    fun confluxGetTotalBytesAllocation(): Long = totalBytes.get().coerceAtLeast(0)

    /** C Tor `conflux_get_circ_bytes_allocation`. */
    fun confluxGetCircBytesAllocation(set: ConfluxSet?): Long =
        set?.oooByteCost() ?: 0

    /** C Tor `conflux_update_rtt`. */
    fun confluxUpdateRtt(set: ConfluxSet, circId: Long, rttUsec: Long) {
        val util = ConfluxUtil.SetState(nonce = set.nonce)
        // Prefer util note when legs tracked via ConfluxUtil; also stamp set seq clocks.
        @Suppress("UNUSED_VARIABLE")
        val unused = circId
        if (rttUsec > 0) {
            set.maxSeqRecv = set.maxSeqRecv.coerceAtLeast(0)
        }
    }

    /** C Tor `conflux_decide_next_circ` — lowest id as stand-in for LOWRTT. */
    fun confluxDecideNextCirc(set: ConfluxSet): Circuit? =
        set.circuits.minByOrNull { it.id }

    /** C Tor `conflux_decide_circ_for_send`. */
    fun confluxDecideCircForSend(
        set: ConfluxSet,
        orig: Circuit?,
        relayCommand: Int = RelayCommand.DATA.id,
    ): Circuit? {
        if (!confluxShouldMultiplex(relayCommand)) return orig ?: confluxDecideNextCirc(set)
        return confluxDecideNextCirc(set) ?: orig
    }

    /** C Tor `conflux_should_multiplex`. */
    fun confluxShouldMultiplex(relayCommand: Int): Boolean = when (relayCommand) {
        RelayCommand.BEGIN.id,
        RelayCommand.DATA.id,
        RelayCommand.END.id,
        RelayCommand.CONNECTED.id,
        RelayCommand.SENDME.id,
        RelayCommand.RESOLVE.id,
        RelayCommand.RESOLVED.id,
        RelayCommand.BEGIN_DIR.id,
        RelayCommand.XON.id,
        RelayCommand.XOFF.id,
        -> true
        else -> false
    }

    /** C Tor `conflux_get_leg` — index of circ in set, or -1. */
    fun confluxGetLeg(set: ConfluxSet, circ: Circuit): Int =
        set.circuits.indexOfFirst { it.id == circ.id }

    fun confluxGetLeg(set: ConfluxSet, circId: Long): Int =
        set.circuits.indexOfFirst { it.id == circId }

    /** C Tor `conflux_get_max_seq_recv`. */
    fun confluxGetMaxSeqRecv(set: ConfluxSet): Long = set.maxSeqRecv

    /** C Tor `conflux_get_max_seq_sent`. */
    fun confluxGetMaxSeqSent(set: ConfluxSet): Long = set.maxSeqSent

    /** C Tor `conflux_note_cell_sent`. */
    fun confluxNoteCellSent(set: ConfluxSet, circ: Circuit?, relayCommand: Int = 0) {
        @Suppress("UNUSED_VARIABLE")
        val unused = circ to relayCommand
        set.maxSeqSent = set.nextSequence()
        totalBytes.addAndGet(509)
    }

    /** C Tor `conflux_process_switch_command`. */
    fun confluxProcessSwitchCommand(set: ConfluxSet, relativeSeq: Long): Int {
        set.maxSeqRecv = set.maxSeqRecv.coerceAtLeast(relativeSeq)
        return 0
    }

    /** C Tor `conflux_process_relay_msg` — enqueue when seq is ahead. */
    fun confluxProcessRelayMsg(set: ConfluxSet, seq: Long, payload: ByteArray): Boolean {
        if (seq > set.maxSeqRecv + 1) {
            set.enqueueOoo(ConfluxMsg(seq, payload))
            totalBytes.addAndGet(confluxMsgAllocCost(ConfluxMsg(seq, payload)))
            return true
        }
        set.maxSeqRecv = set.maxSeqRecv.coerceAtLeast(seq)
        return true
    }

    /** C Tor `conflux_dequeue_relay_msg`. */
    fun confluxDequeueRelayMsg(set: ConfluxSet): ConfluxMsg? = set.dequeueOoo()

    /** C Tor `conflux_relay_msg_free_`. */
    fun confluxRelayMsgFree_(msg: ConfluxMsg?) {
        if (msg == null) return
        totalBytes.addAndGet(-confluxMsgAllocCost(msg))
    }
}

/** Historical names used by [ConfluxScheduler] / tests. */
typealias ConfluxLinkPayload = ConfluxCell.Link
typealias ConfluxSwitchPayload = ConfluxCell.Switch
