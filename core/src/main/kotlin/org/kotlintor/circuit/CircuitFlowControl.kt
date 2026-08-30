package org.kotlintor.circuit

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Classic circuit-level SENDME windows (C Tor `sendme.c` / tor-spec §7.3).
 *
 * Inventory: `L1:core/or/sendme.c` (windows) — prop324 XON/XOFF lives in
 * [CongestionControlFlow].
 *
 * Defaults: circwindow=1000, increment=100. Authenticated SENDME version 1.
 */
class CircuitFlowControl(
    private var deliverWindow: Int = 1000,
    private var packageWindow: Int = 1000,
    private val increment: Int = 100,
) {
    private val mutex = Mutex()
    private val packageCredit = Channel<Unit>(Channel.UNLIMITED)

    /** After successfully decrypting an inbound RELAY_DATA for this circuit. */
    suspend fun onInboundData(digestAfterCell: ByteArray): ByteArray? = mutex.withLock {
        deliverWindow--
        check(deliverWindow >= 0) { "circuit deliver window underflow" }
        if (deliverWindow % increment == 0) {
            return@withLock buildSendmeV1(digestAfterCell)
        }
        null
    }

    /**
     * Before sending an outbound RELAY_DATA cell.
     * @return true when a digest should be recorded for the next inbound SENDME
     *   (C Tor `sendme_record_cell_digest_on_circ` cadence).
     */
    suspend fun beforeOutboundData(): Boolean {
        while (true) {
            val (wait, record) = mutex.withLock {
                if (packageWindow > 0) {
                    packageWindow--
                    val record = packageWindow % increment == 0
                    false to record
                } else {
                    true to false
                }
            }
            if (!wait) return record
            packageCredit.receive()
        }
    }

    /**
     * Inbound circuit-level SENDME (stream_id=0). Credits package window only
     * when [Sendme.isValid] accepts the payload against [digests].
     * @return false if the cell was rejected (no credit).
     */
    suspend fun onInboundSendme(payload: ByteArray, digests: Sendme.DigestQueue): Boolean {
        if (!Sendme.isValid(digests, payload)) return false
        mutex.withLock {
            packageWindow += increment
        }
        packageCredit.trySend(Unit)
        return true
    }
}
