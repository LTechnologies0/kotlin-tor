package org.kotlintor.circuit

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Classic circuit-level windows (tor-spec §7.3) without prop324 congestion control.
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

    /** Before sending an outbound RELAY_DATA cell. */
    suspend fun beforeOutboundData() {
        while (true) {
            val wait = mutex.withLock {
                if (packageWindow > 0) {
                    packageWindow--
                    false
                } else {
                    true
                }
            }
            if (!wait) return
            packageCredit.receive()
        }
    }

    /** Inbound circuit-level SENDME (stream_id=0). */
    suspend fun onInboundSendme() {
        mutex.withLock {
            packageWindow += increment
        }
        packageCredit.trySend(Unit)
    }
}

/** Build authenticated SENDME v1 body from a 20-byte digest. */
fun buildSendmeV1(digest20: ByteArray): ByteArray {
    require(digest20.size >= 20)
    return byteArrayOf(1, 0, 20) + digest20.copyOf(20)
}
