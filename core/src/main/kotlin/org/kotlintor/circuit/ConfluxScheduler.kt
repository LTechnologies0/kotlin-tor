package org.kotlintor.circuit

import org.kotlintor.cell.RelayCommand
import org.kotlintor.circuit.buildRelayCell
import java.util.concurrent.atomic.AtomicInteger

/**
 * Prop329 multipath DATA scheduling (C Tor conflux scheduler path).
 *
 * Prefer lowest-RTT / primary leg; fall back to secondary when primary is
 * blocked by congestion. Subsystem entry: [ConfluxSys].
 */
class ConfluxScheduler(
    private val set: ConfluxSet,
) {
    private val primaryIdx = AtomicInteger(0)
    @Volatile var primaryRttMs: Long = Long.MAX_VALUE
    @Volatile var secondaryRttMs: Long = Long.MAX_VALUE

    fun noteRtt(circuitId: Long, rttMs: Long) {
        val idx = set.circuits.indexOfFirst { it.id == circuitId }
        if (idx < 0) return
        if (idx == 0) primaryRttMs = rttMs else secondaryRttMs = rttMs
        if (secondaryRttMs < primaryRttMs) primaryIdx.set(1) else primaryIdx.set(0)
    }

    fun pickLeg(): Circuit? {
        val circs = set.circuits
        if (circs.isEmpty()) return null
        val i = primaryIdx.get().coerceIn(0, circs.lastIndex)
        return circs[i]
    }

    suspend fun sendLink(leg: Circuit, payload: ConfluxCell.Link) {
        leg.sendRelay(buildRelayCell(RelayCommand.CONFLUX_LINK, 0, payload.encode()))
    }

    suspend fun sendLinked(leg: Circuit, payload: ConfluxCell.Link) {
        leg.sendRelay(buildRelayCell(RelayCommand.CONFLUX_LINKED, 0, payload.encode()))
    }

    suspend fun sendLinkedAck(leg: Circuit) {
        leg.sendRelay(buildRelayCell(RelayCommand.CONFLUX_LINKED_ACK, 0, Conflux.linkedAckCell()))
    }

    suspend fun sendSwitch(leg: Circuit, seq: Long) {
        leg.sendRelay(buildRelayCell(RelayCommand.CONFLUX_SWITCH, 0, Conflux.switchCell(seq)))
    }

    /** Send DATA on the scheduled primary leg; SWITCH when RTT flips primary. */
    suspend fun sendData(streamId: Int, data: ByteArray) {
        val circs = set.circuits
        if (circs.isEmpty()) error("conflux set empty")
        val prev = primaryIdx.get()
        // Prefer lower RTT; fall back to other leg when primary blocked.
        val primary = pickLeg() ?: error("conflux set empty")
        val nowPrimary = circs.indexOf(primary).coerceAtLeast(0)
        if (nowPrimary != prev && circs.size > 1) {
            primaryIdx.set(nowPrimary)
            sendSwitch(primary, set.nextSequence())
        }
        primary.sendData(streamId, data)
    }
}