package org.kotlintor.circuit

import org.kotlintor.cell.RelayCommand
import org.kotlintor.util.SecureRandomSource
import org.kotlintor.util.u64be
import org.kotlintor.util.readU64be

/**
 * Prop329 Conflux (multipath) — LINK/LINKED/SWITCH codecs + set state.
 * Full multipath DATA scheduling still lite; handshake cells are wire-ready.
 */
class ConfluxSet(
    val nonce: ByteArray,
    val circuits: MutableList<Circuit> = mutableListOf(),
) {
    @Volatile var nextSeq: Long = 0
        private set
    @Volatile var linked: Boolean = false

    fun add(circuit: Circuit) {
        if (circuits.none { it.id == circuit.id }) circuits += circuit
    }

    fun nextSequence(): Long = synchronized(this) { nextSeq++ }

    fun size(): Int = circuits.size
}

object Conflux {
    const val VERSION: Int = 0x01

    enum class DesiredUx(val id: Int) {
        NO_OPINION(0),
        MIN_LATENCY(1),
        LOW_MEM_LATENCY(2),
        HIGH_THROUGHPUT(3),
        LOW_MEM_THROUGHPUT(4),
        ;

        companion object {
            fun fromId(id: Int): DesiredUx = entries.firstOrNull { it.id == id } ?: NO_OPINION
        }
    }

    data class LinkPayload(
        val nonce: ByteArray,
        val lastSeqnoSent: Long = 0,
        val lastSeqnoRecv: Long = 0,
        val desiredUx: DesiredUx = DesiredUx.NO_OPINION,
    ) {
        fun encode(): ByteArray {
            require(nonce.size == 32)
            return byteArrayOf(VERSION.toByte()) +
                nonce +
                u64be(lastSeqnoSent) +
                u64be(lastSeqnoRecv) +
                byteArrayOf(desiredUx.id.toByte())
        }
    }

    data class SwitchPayload(val sequnce: Long) {
        fun encode(): ByteArray = u64be(sequnce)
    }

    fun newNonce(): ByteArray = SecureRandomSource.nextBytes(32)

    fun parseLink(data: ByteArray): LinkPayload {
        require(data.size >= 1 + 32 + 8 + 8 + 1) { "CONFLUX_LINK too short" }
        require(data[0].toInt() and 0xff == VERSION) { "unsupported conflux version ${data[0]}" }
        var o = 1
        val nonce = data.copyOfRange(o, o + 32); o += 32
        val sent = readU64be(data, o); o += 8
        val recv = readU64be(data, o); o += 8
        val ux = DesiredUx.fromId(data[o].toInt() and 0xff)
        return LinkPayload(nonce, sent, recv, ux)
    }

    fun parseSwitch(data: ByteArray): SwitchPayload {
        require(data.size >= 8)
        return SwitchPayload(readU64be(data, 0))
    }

    fun linkCell(payload: LinkPayload) = payload.encode()
    fun linkedCell(payload: LinkPayload) = payload.encode()
    fun linkedAckCell(): ByteArray = ByteArray(0)
    fun switchCell(seq: Long) = SwitchPayload(seq).encode()

    val linkCommand: RelayCommand get() = RelayCommand.CONFLUX_LINK
    val linkedCommand: RelayCommand get() = RelayCommand.CONFLUX_LINKED
    val linkedAckCommand: RelayCommand get() = RelayCommand.CONFLUX_LINKED_ACK
    val switchCommand: RelayCommand get() = RelayCommand.CONFLUX_SWITCH
}
