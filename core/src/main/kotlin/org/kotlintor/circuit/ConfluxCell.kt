package org.kotlintor.circuit

import org.kotlintor.cell.RelayCommand
import org.kotlintor.util.SecureRandomSource
import org.kotlintor.util.readU64be
import org.kotlintor.util.u64be

/**
 * Conflux LINK/LINKED/SWITCH cell codecs (C Tor `conflux_cell.c`).
 *
 * Inventory: `L1:core/or/conflux_cell.c`
 *
 * Wire layout matches trunnel `trn_cell_conflux_link` v1:
 * version(1) | nonce(32) | last_seqno_sent(8) | last_seqno_recv(8) | desired_ux(1).
 */
object ConfluxCell {
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

    data class Link(
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

    data class Switch(val sequence: Long) {
        fun encode(): ByteArray = u64be(sequence)
    }

    fun newNonce(): ByteArray = SecureRandomSource.nextBytes(32)

    /** C Tor `build_link_cell` / LINKED share the same payload. */
    fun buildLink(link: Link): ByteArray = link.encode()

    /** C Tor `build_link_cell` alias. */
    fun buildLinkCell(link: Link): ByteArray = buildLink(link)

    fun buildLinked(link: Link): ByteArray = link.encode()

    fun buildLinkedAck(): ByteArray = ByteArray(0)

    fun buildSwitch(seq: Long): ByteArray = Switch(seq).encode()

    fun parseLink(data: ByteArray): Link {
        require(data.size >= 1 + 32 + 8 + 8 + 1) { "CONFLUX_LINK too short" }
        require(data[0].toInt() and 0xff == VERSION) { "unsupported conflux version ${data[0]}" }
        var o = 1
        val nonce = data.copyOfRange(o, o + 32); o += 32
        val sent = readU64be(data, o); o += 8
        val recv = readU64be(data, o); o += 8
        val ux = DesiredUx.fromId(data[o].toInt() and 0xff)
        return Link(nonce, sent, recv, ux)
    }

    fun parseSwitch(data: ByteArray): Switch {
        require(data.size >= 8)
        return Switch(readU64be(data, 0))
    }

    /** C Tor `conflux_cell_new_link`. */
    fun confluxCellNewLink(
        nonce: ByteArray = newNonce(),
        lastSeqnoSent: Long = 0,
        lastSeqnoRecv: Long = 0,
        desiredUx: DesiredUx = DesiredUx.NO_OPINION,
    ): Link = Link(nonce, lastSeqnoSent, lastSeqnoRecv, desiredUx)

    /** C Tor `conflux_cell_parse_link`. */
    fun confluxCellParseLink(data: ByteArray): Link = parseLink(data)

    /** C Tor `conflux_cell_parse_linked`. */
    fun confluxCellParseLinked(data: ByteArray): Link = parseLink(data)

    /** C Tor `conflux_cell_parse_switch`. */
    fun confluxCellParseSwitch(data: ByteArray): Switch = parseSwitch(data)

    /** C Tor `conflux_cell_send_link` — encode LINK payload. */
    fun confluxCellSendLink(link: Link): ByteArray = buildLink(link)

    /** C Tor `conflux_cell_send_linked`. */
    fun confluxCellSendLinked(link: Link): ByteArray = buildLinked(link)

    /** C Tor `conflux_cell_send_linked_ack`. */
    fun confluxCellSendLinkedAck(): ByteArray = buildLinkedAck()

    /** C Tor `conflux_send_switch_command`. */
    fun confluxSendSwitchCommand(relativeSeq: Long): ByteArray = buildSwitch(relativeSeq)

    val linkCommand: RelayCommand get() = RelayCommand.CONFLUX_LINK
    val linkedCommand: RelayCommand get() = RelayCommand.CONFLUX_LINKED
    val linkedAckCommand: RelayCommand get() = RelayCommand.CONFLUX_LINKED_ACK
    val switchCommand: RelayCommand get() = RelayCommand.CONFLUX_SWITCH
}
