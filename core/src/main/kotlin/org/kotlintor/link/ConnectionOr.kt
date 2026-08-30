package org.kotlintor.link

import kotlinx.coroutines.CoroutineScope
import org.kotlintor.cell.CellCommand
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * OR connection helpers (C Tor `connection_or.c`).
 *
 * Inventory: `L1:core/or/connection_or.c`
 *
 * Implementation: [OrConnection].
 */
object ConnectionOr {
    private val identityMap = ConcurrentHashMap<String, OrChannel>()
    private val brokenStates = AtomicInteger(0)
    private val brokenMap = ConcurrentHashMap<String, Int>()

    fun newClient(
        peerHost: String,
        peerPort: Int,
        scope: CoroutineScope,
    ): OrConnection = OrConnection(peerHost, peerPort, scope)

    fun peerFingerprint(conn: OrConnection): ByteArray? = conn.peerIdentityFingerprint

    fun negotiatedVersion(conn: OrConnection): Int = conn.negotiatedVersion

    /**
     * C Tor `cell_pack` — circ_id(u32be) + command + payload (link proto ≥ 4).
     */
    fun cellPack(circId: Long, command: CellCommand, payload: ByteArray): ByteArray {
        val out = ByteArray(4 + 1 + payload.size)
        out[0] = ((circId ushr 24) and 0xff).toByte()
        out[1] = ((circId ushr 16) and 0xff).toByte()
        out[2] = ((circId ushr 8) and 0xff).toByte()
        out[3] = (circId and 0xff).toByte()
        out[4] = command.id.toByte()
        System.arraycopy(payload, 0, out, 5, payload.size)
        return out
    }

    // --- C Tor connection_or.h op aliases (L3) ---

    data class HandshakeState(
        var versionsSent: Boolean = false,
        var certsReceived: Boolean = false,
        var authenticated: Boolean = false,
        var linkVersion: Int = 0,
    )

    /** C Tor `clear_broken_connection_map`. */
    fun clearBrokenConnectionMap() {
        brokenMap.clear()
        brokenStates.set(0)
    }

    /** C Tor `connection_init_or_handshake_state`. */
    fun connectionInitOrHandshakeState(): HandshakeState = HandshakeState()

    /** C Tor `connection_or_about_to_close`. */
    fun connectionOrAboutToClose(ch: OrChannel) {
        Channel.changeState(ch, ChannelState.CLOSING)
    }

    /** C Tor `connection_or_clear_identity`. */
    fun connectionOrClearIdentity(ch: OrChannel) {
        Channel.clearIdentityDigest(ch)
        identityMap.entries.removeIf { it.value.globalId == ch.globalId }
    }

    /** C Tor `connection_or_clear_identity_map`. */
    fun connectionOrClearIdentityMap() = identityMap.clear()

    /** C Tor `connection_or_client_learned_peer_id`. */
    fun connectionOrClientLearnedPeerId(ch: OrChannel, identityHex: String) {
        Channel.addToDigestMap(ch, identityHex)
        identityMap[identityHex] = ch
    }

    /** C Tor `connection_or_client_used`. */
    fun connectionOrClientUsed(ch: OrChannel) {
        ch.isClient = true
    }

    /** C Tor `connection_or_close_normally`. */
    fun connectionOrCloseNormally(ch: OrChannel) = Channel.close(ch)

    /** C Tor `connection_or_connect_failed`. */
    fun connectionOrConnectFailed(ch: OrChannel) {
        Channel.changeState(ch, ChannelState.ERROR)
        brokenStates.incrementAndGet()
    }

    /** C Tor `connection_or_digest_is_known_relay`. */
    fun connectionOrDigestIsKnownRelay(identityHex: String): Boolean =
        identityMap.containsKey(identityHex) || Channel.checkForDuplicates(identityHex)

    /** C Tor `connection_or_event_status`. */
    fun connectionOrEventStatus(ch: OrChannel): String =
        "ORCONN ${ch.remoteAddr}:${ch.remotePort} ${ch.state}"

    /** C Tor `connection_or_finished_connecting`. */
    fun connectionOrFinishedConnecting(ch: OrChannel) = Channel.changeStateOpen(ch)

    /** C Tor `connection_or_finished_flushing`. */
    fun connectionOrFinishedFlushing(ch: OrChannel): Boolean = !Channel.hasQueuedWrites(ch)

    /** C Tor `connection_or_flushed_some`. */
    fun connectionOrFlushedSome(ch: OrChannel, nbytes: Int): Int {
        var left = nbytes
        while (left > 0 && ch.cellsQueued > 0) {
            val p = ch.popOut() ?: break
            left -= p.size
            ch.bytesWrittenAccount(p.size)
        }
        return nbytes - left.coerceAtLeast(0)
    }

    /** C Tor `connection_or_get_alleged_ed25519_id`. */
    fun connectionOrGetAllegedEd25519Id(ch: OrChannel): ByteArray? =
        ch.ed25519Identity?.copyOf()

    /** C Tor `connection_or_group_set_badness_`. */
    fun connectionOrGroupSetBadness(identityHex: String) {
        brokenMap[identityHex] = (brokenMap[identityHex] ?: 0) + 1
        Channel.findByRemoteIdentity(identityHex)?.let { Channel.closeForError(it) }
    }

    /** C Tor `connection_or_init_conn_from_address`. */
    fun connectionOrInitConnFromAddress(addr: String, port: Int): OrChannel =
        Channel.init(addr, port)

    /** C Tor `connection_or_notify_error`. */
    fun connectionOrNotifyError(ch: OrChannel, msg: String): String {
        Channel.closeForError(ch)
        return "ORCONN_ERROR $msg"
    }

    /** C Tor `connection_or_num_cells_writeable`. */
    fun connectionOrNumCellsWriteable(ch: OrChannel, limit: Int = 32): Int =
        (limit - ch.cellsQueued).coerceAtLeast(0)

    /** C Tor `connection_or_process_inbuf`. */
    fun connectionOrProcessInbuf(ch: OrChannel, available: Int): Int {
        val n = available.coerceAtLeast(0)
        if (n > 0) ch.appendIn(ByteArray(n))
        return n
    }
    /** C Tor `connection_or_reached_eof`. */
    fun connectionOrReachedEof(ch: OrChannel) = connectionOrAboutToClose(ch)

    /** C Tor `connection_or_report_broken_states`. */
    fun connectionOrReportBrokenStates(): Int = brokenStates.get() + brokenMap.values.sum()

    /** C Tor `connection_or_send_versions`. */
    fun connectionOrSendVersions(versions: List<Int> = listOf(3, 4, 5)): ByteArray {
        val out = ByteArray(versions.size * 2)
        versions.forEachIndexed { i, v ->
            out[i * 2] = ((v ushr 8) and 0xff).toByte()
            out[i * 2 + 1] = (v and 0xff).toByte()
        }
        return out
    }

    /** C Tor `connection_or_set_canonical`. */
    fun connectionOrSetCanonical(ch: OrChannel, canonical: Boolean = true) {
        ch.canonical = canonical
    }
}
