package org.kotlintor.circuit

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.ArrayDeque

/**
 * Prop324 circuit congestion control (Vegas subset), off-wire until CREATE2
 * `CC_FIELD_REQUEST` is enabled.
 *
 * Defaults match current consensus: `cc_sendme_inc=31`, `cc_cwnd_init=124`,
 * `cc_cwnd_min=31`, `cc_alg=Vegas`.
 *
 * SENDME bodies use authenticated v1 digests while CGO/tor1 digests remain the
 * hop-crypto signal; timestamps are tracked locally for RTT.
 */
class CongestionControl(
    private val sendmeInc: Int = DEFAULT_SENDME_INC,
    private var cwnd: Int = DEFAULT_CWND_INIT,
    private val cwndMin: Int = DEFAULT_CWND_MIN,
    private val cwndMax: Int = DEFAULT_CWND_MAX,
    private val cwndInc: Int = 31,
    private val alpha: Int = 3 * 31, // cells of queue_use → increase
    private val beta: Int = 4 * 31, // cells of queue_use → decrease
    private val delta: Int = 5 * 31,
) {
    private val mutex = Mutex()
    private val packageCredit = Channel<Unit>(Channel.UNLIMITED)
    private var inflight = 0
    private var deliverCount = 0
    private var rttMinMs: Long = Long.MAX_VALUE
    private var rttEwmaMs: Long = 0
    private var inSlowStart = true
    private val sentAt = ArrayDeque<Long>()

    val congestionWindow: Int get() = cwnd
    val inFlight: Int get() = inflight
    val increment: Int get() = sendmeInc

    suspend fun beforeOutboundData() {
        while (true) {
            val wait = mutex.withLock {
                if (inflight < cwnd) {
                    inflight++
                    sentAt.addLast(System.nanoTime())
                    false
                } else {
                    true
                }
            }
            if (!wait) return
            packageCredit.receive()
        }
    }

    /** After inbound RELAY_DATA; may return a SENDME v1 body to transmit. */
    suspend fun onInboundData(digestAfterCell: ByteArray): ByteArray? = mutex.withLock {
        deliverCount++
        if (deliverCount % sendmeInc == 0) {
            return@withLock buildSendmeV1(digestAfterCell)
        }
        null
    }

    /** Inbound circuit-level SENDME. */
    suspend fun onInboundSendme() {
        mutex.withLock {
            val now = System.nanoTime()
            // Consume up to sendmeInc send timestamps for RTT (oldest first).
            var samples = 0
            while (samples < sendmeInc && sentAt.isNotEmpty()) {
                val t0 = sentAt.removeFirst()
                val rtt = ((now - t0) / 1_000_000L).coerceAtLeast(1)
                if (rtt < rttMinMs) rttMinMs = rtt
                rttEwmaMs = if (rttEwmaMs == 0L) rtt else (rttEwmaMs * 7 + rtt) / 8
                samples++
            }
            inflight = (inflight - sendmeInc).coerceAtLeast(0)

            if (rttMinMs != Long.MAX_VALUE && rttEwmaMs > 0) {
                // queue_use ≈ cwnd * (1 - rtt_min/rtt_ewma)  (Vegas cwnd BDP mix = 100%)
                val queueUse = if (rttEwmaMs <= rttMinMs) {
                    0
                } else {
                    ((cwnd.toLong() * (rttEwmaMs - rttMinMs)) / rttEwmaMs).toInt()
                }
                if (inSlowStart) {
                    if (queueUse > delta) {
                        inSlowStart = false
                        cwnd = (cwnd * 3 / 4).coerceAtLeast(cwndMin)
                    } else {
                        cwnd = (cwnd + sendmeInc).coerceAtMost(cwndMax)
                    }
                } else {
                    when {
                        queueUse < alpha -> cwnd = (cwnd + cwndInc).coerceAtMost(cwndMax)
                        queueUse > beta -> cwnd = (cwnd - cwndInc).coerceAtLeast(cwndMin)
                    }
                }
            }
        }
        packageCredit.trySend(Unit)
    }

    companion object {
        const val DEFAULT_SENDME_INC = 31
        const val DEFAULT_CWND_INIT = 4 * 31
        const val DEFAULT_CWND_MIN = 31
        const val DEFAULT_CWND_MAX = 5000

        fun fromNegotiatedSendmeInc(inc: Int): CongestionControl {
            require(inc in 1..254)
            return CongestionControl(
                sendmeInc = inc,
                cwnd = (4 * inc).coerceAtLeast(inc),
                cwndMin = inc,
                cwndInc = inc,
                alpha = 3 * inc,
                beta = 4 * inc,
                delta = 5 * inc,
            )
        }
    }
}
