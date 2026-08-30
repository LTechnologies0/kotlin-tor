package org.kotlintor.circuit

import org.kotlintor.cell.CellCommand
import org.kotlintor.cell.RelayCommand
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/**
 * Relay cell processing helpers (C Tor `relay.c`).
 *
 * Inventory: `L1:core/or/relay.c`
 */
object Relay {
    const val RESOLVED_TYPE_IPV4: Int = 4
    const val RESOLVED_TYPE_IPV6: Int = 6
    const val RESOLVED_TYPE_HOSTNAME: Int = 0
    const val RELAY_PAYLOAD_SIZE_MAX: Int = 498

    /** C Tor `address_ttl_t`. */
    data class AddressTtl(
        val address: InetAddress?,
        val hostname: String? = null,
        val ttl: Int = 0,
    )

    fun isRelayCommand(cmd: CellCommand): Boolean =
        cmd == CellCommand.RELAY || cmd == CellCommand.RELAY_EARLY

    fun isExtendFamily(cmd: RelayCommand): Boolean =
        cmd == RelayCommand.EXTEND || cmd == RelayCommand.EXTEND2 ||
            cmd == RelayCommand.EXTENDED || cmd == RelayCommand.EXTENDED2

    fun isBeginFamily(cmd: RelayCommand): Boolean =
        cmd == RelayCommand.BEGIN || cmd == RelayCommand.BEGIN_DIR

    fun isData(cmd: RelayCommand): Boolean = cmd == RelayCommand.DATA

    fun isEnd(cmd: RelayCommand): Boolean = cmd == RelayCommand.END

    fun isSendme(cmd: RelayCommand): Boolean = cmd == RelayCommand.SENDME

    fun earlyAllowed(cmd: RelayCommand): Boolean =
        isExtendFamily(cmd) || cmd == RelayCommand.ESTABLISH_INTRO ||
            cmd == RelayCommand.ESTABLISH_RENDEZVOUS

    // --- C Tor `relay.h` op aliases (L3) ---

    /** C Tor `address_ttl_free_`. */
    fun addressTtlFree(addr: AddressTtl?) {
        // Kotlin GC; wipe hostname reference for API parity.
        addr?.hostname
    }

    /**
     * C Tor `append_address_to_payload`.
     * @return bytes written, or -1 on error
     */
    fun appendAddressToPayload(payloadOut: ByteArray, offset: Int = 0, addr: InetAddress): Int {
        return when (addr) {
            is Inet4Address -> {
                if (payloadOut.size < offset + 6) return -1
                payloadOut[offset] = RESOLVED_TYPE_IPV4.toByte()
                payloadOut[offset + 1] = 4
                val raw = addr.address
                System.arraycopy(raw, 0, payloadOut, offset + 2, 4)
                6
            }
            is Inet6Address -> {
                if (payloadOut.size < offset + 18) return -1
                payloadOut[offset] = RESOLVED_TYPE_IPV6.toByte()
                payloadOut[offset + 1] = 16
                val raw = addr.address
                System.arraycopy(raw, 0, payloadOut, offset + 2, 16)
                18
            }
            else -> -1
        }
    }

    /** C Tor `decode_address_from_payload`. */
    fun decodeAddressFromPayload(payload: ByteArray, offset: Int = 0): Pair<InetAddress, Int>? {
        if (payload.size < offset + 2) return null
        val type = payload[offset].toInt() and 0xff
        val len = payload[offset + 1].toInt() and 0xff
        if (payload.size < offset + 2 + len) return null
        val next = offset + 2 + len
        return when (type) {
            RESOLVED_TYPE_IPV4 -> {
                if (len != 4) return null
                InetAddress.getByAddress(payload.copyOfRange(offset + 2, offset + 6)) to next
            }
            RESOLVED_TYPE_IPV6 -> {
                if (len != 16) return null
                InetAddress.getByAddress(payload.copyOfRange(offset + 2, offset + 18)) to next
            }
            else -> null
        }
    }

    /** C Tor `cell_queue_append` (facade). */
    fun cellQueueAppend(queue: CellQueue, payload: ByteArray): Boolean =
        CellQueue.cellQueueAppend(queue, payload)

    fun cellQueueAppendPackedCopy(queue: CellQueue, payload: ByteArray): Boolean =
        CellQueue.cellQueueAppendPackedCopy(queue, payload)

    fun cellQueueClear(queue: CellQueue) = CellQueue.cellQueueClear(queue)

    fun cellQueueInit(maxCells: Int = CellQueue.DEFAULT_MAX): CellQueue =
        CellQueue.cellQueueInit(maxCells)

    fun cellQueuePop(queue: CellQueue): ByteArray? = CellQueue.cellQueuePop(queue)

    fun cellQueuesCheckSize(softCapBytes: Long = 64L * 1024 * 1024): Boolean =
        CellQueue.cellQueuesCheckSize(softCapBytes)

    fun cellQueuesGetTotalAllocation(): Long = CellQueue.cellQueuesGetTotalAllocation()

    fun destroyCellQueueAppend(queue: DestroyCellQueue, circId: Long, reason: Int = 0) =
        queue.destroyCellQueueAppend(circId, reason)

    fun appendCellToCircuitQueue(mux: CircuitMux, circId: Long, payload: ByteArray): Boolean =
        mux.appendCellToCircuitQueue(circId, payload)

    fun circuitClearCellQueue(mux: CircuitMux, circId: Long) = mux.circuitClearCellQueue(circId)

    fun channelUnlinkAllCircuits(mux: CircuitMux) = CircuitMux.channelUnlinkAllCircuits(mux)

    /** C Tor `circuit_get_relay_format` — 0 = classic, 1 = v1. */
    fun circuitGetRelayFormat(useV1: Boolean = false): Int = if (useV1) 1 else 0

    /** C Tor `circuit_max_relay_payload`. */
    fun circuitMaxRelayPayload(format: Int = 0): Int =
        if (format == 1) RELAY_PAYLOAD_SIZE_MAX - 10 else RELAY_PAYLOAD_SIZE_MAX

    /** C Tor `circuit_receive_relay_cell` — validate command family. */
    fun circuitReceiveRelayCell(cmd: CellCommand): Boolean = isRelayCommand(cmd)

    /** C Tor `circuit_reset_sendme_randomness` (no-op until RNG wired). */
    fun circuitResetSendmeRandomness() = Unit

    /**
     * C Tor `connected_cell_parse` — optional TTL after IPv4/IPv6.
     * Layout: type(1) len(1) addr(len) [ttl u32be]
     */
    fun connectedCellParse(payload: ByteArray): Pair<InetAddress, Int>? {
        val (addr, next) = decodeAddressFromPayload(payload) ?: return null
        val ttl =
            if (payload.size >= next + 4) {
                ((payload[next].toInt() and 0xff) shl 24) or
                    ((payload[next + 1].toInt() and 0xff) shl 16) or
                    ((payload[next + 2].toInt() and 0xff) shl 8) or
                    (payload[next + 3].toInt() and 0xff)
            } else {
                0
            }
        return addr to ttl
    }

    /** C Tor `connection_edge_consider_sending_sendme` — window threshold. */
    fun connectionEdgeConsiderSendingSendme(deliverWindow: Int, increment: Int = 50): Boolean =
        deliverWindow <= increment

    /** C Tor `connection_edge_get_inbuf_bytes_to_package`. */
    fun connectionEdgeGetInbufBytesToPackage(available: Int, maxPayload: Int = RELAY_PAYLOAD_SIZE_MAX): Int =
        available.coerceIn(0, maxPayload)

    /** C Tor `connection_edge_package_raw_inbuf` — slice up to max payload. */
    fun connectionEdgePackageRawInbuf(buf: ByteArray, maxPayload: Int = RELAY_PAYLOAD_SIZE_MAX): ByteArray =
        buf.copyOf(buf.size.coerceAtMost(maxPayload))

    /** C Tor `connection_edge_process_relay_cell` — command dispatch stub. */
    fun connectionEdgeProcessRelayCell(cmd: RelayCommand): Boolean =
        isBeginFamily(cmd) || isData(cmd) || isEnd(cmd) || isSendme(cmd) || isExtendFamily(cmd)

    /** C Tor `connection_edge_process_resolved_cell`. */
    fun connectionEdgeProcessResolvedCell(payload: ByteArray): List<AddressTtl> {
        val out = ArrayList<AddressTtl>()
        var o = 0
        while (o + 2 <= payload.size) {
            val type = payload[o].toInt() and 0xff
            val len = payload[o + 1].toInt() and 0xff
            if (o + 2 + len > payload.size) break
            when (type) {
                RESOLVED_TYPE_HOSTNAME -> {
                    val host = payload.copyOfRange(o + 2, o + 2 + len).toString(Charsets.UTF_8)
                    out += AddressTtl(null, host, 0)
                    o += 2 + len
                }
                else -> {
                    val decoded = decodeAddressFromPayload(payload, o) ?: break
                    out += AddressTtl(decoded.first, null, 0)
                    o = decoded.second
                }
            }
            if (o + 4 <= payload.size) {
                // optional ttl ignored for list parse
            }
        }
        return out
    }

    /** C Tor `connection_edge_send_command` — validate sendable relay cmd. */
    fun connectionEdgeSendCommand(cmd: RelayCommand): Boolean =
        connectionEdgeProcessRelayCell(cmd)
}
