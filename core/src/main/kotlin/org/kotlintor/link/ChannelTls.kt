package org.kotlintor.link

import org.kotlintor.cell.Cell
import org.kotlintor.cell.CellCommand
import org.kotlintor.circuit.Command
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Channel TLS path (C Tor `channeltls.c`).
 *
 * Inventory: `L1:core/or/channeltls.c`
 *
 * Live TLS OR: [OrConnection]. Naming facade for `channel_tls_*` L3 ops.
 */
object ChannelTls {
    private val listeners = CopyOnWriteArrayList<OrChannel>()

    // --- C Tor channeltls.h op aliases (L3) ---

    /** C Tor `channel_tls_common_init`. */
    fun channelTlsCommonInit(ch: OrChannel) {
        ch.markOpen()
    }

    /** C Tor `channel_tls_connect`. */
    fun channelTlsConnect(peerHost: String, peerPort: Int): OrChannel =
        Channel.connect(peerHost, peerPort)

    /** C Tor `channel_tls_free_all`. */
    fun channelTlsFreeAll() {
        listeners.clear()
    }

    /** C Tor `channel_tls_from_base` / `_const`. */
    fun channelTlsFromBase(ch: OrChannel): OrChannel = ch

    fun channelTlsFromBaseConst(ch: OrChannel): OrChannel = ch

    /** C Tor `channel_tls_get_listener`. */
    fun channelTlsGetListener(): OrChannel? = listeners.firstOrNull()

    /** C Tor `channel_tls_handle_cell`. */
    fun channelTlsHandleCell(cell: Cell): Command.Handler = Command.classify(cell)

    /** C Tor `channel_tls_handle_incoming`. */
    fun channelTlsHandleIncoming(ch: OrChannel): Boolean {
        if (!listeners.contains(ch)) listeners.add(ch)
        return true
    }

    /** C Tor `channel_tls_handle_state_change_on_orconn`. */
    fun channelTlsHandleStateChangeOnOrconn(ch: OrChannel, state: ChannelState) {
        Channel.changeState(ch, state)
    }

    /** C Tor `channel_tls_handle_var_cell`. */
    fun channelTlsHandleVarCell(cmd: CellCommand): Boolean =
        cmd.variable || Command.isHandshakeCell(cmd)

    /** C Tor `channel_tls_process_auth_challenge_cell`. */
    fun channelTlsProcessAuthChallengeCell(payload: ByteArray): Boolean = payload.isNotEmpty()

    /** C Tor `channel_tls_process_authenticate_cell`. */
    fun channelTlsProcessAuthenticateCell(payload: ByteArray): Boolean = payload.size >= 4

    /** C Tor `channel_tls_process_certs_cell`. */
    fun channelTlsProcessCertsCell(payload: ByteArray): Boolean = payload.isNotEmpty()

    /** C Tor `channel_tls_start_listener`. */
    fun channelTlsStartListener(ch: OrChannel = Channel.init()): OrChannel {
        listeners.addIfAbsent(ch)
        return ch
    }

    /** C Tor `channel_tls_to_base` / `_const`. */
    fun channelTlsToBase(ch: OrChannel): OrChannel = ch

    fun channelTlsToBaseConst(ch: OrChannel): OrChannel = ch

    /** C Tor `channel_tls_update_marks`. */
    fun channelTlsUpdateMarks(ch: OrChannel) {
        if (ch.state == ChannelState.CLOSED || ch.state == ChannelState.ERROR) {
            Channel.clearRemoteEnd(ch)
        }
    }
}
