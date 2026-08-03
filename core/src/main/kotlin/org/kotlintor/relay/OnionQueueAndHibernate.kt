package org.kotlintor.relay

import java.util.ArrayDeque
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Onion handshake queue (C Tor `onion_queue.c`).
 *
 * Limits concurrent CREATE/CREATE2 handshakes and applies optional max delay.
 */
class OnionQueue(
    private val maxPending: Int = 100,
    private val maxDelayMs: Long = 0,
) {
    data class Job(val circId: Long, val enqueuedAtMs: Long, val payload: ByteArray)

    private val lock = ReentrantLock()
    private val q = ArrayDeque<Job>()

    fun tryEnqueue(circId: Long, payload: ByteArray, nowMs: Long = System.currentTimeMillis()): Boolean =
        lock.withLock {
            if (q.size >= maxPending) return false
            q.addLast(Job(circId, nowMs, payload.copyOf()))
            true
        }

    fun poll(nowMs: Long = System.currentTimeMillis()): Job? = lock.withLock {
        while (q.isNotEmpty()) {
            val j = q.first()
            if (maxDelayMs > 0 && nowMs - j.enqueuedAtMs > maxDelayMs) {
                q.removeFirst()
                continue // drop expired
            }
            return q.removeFirst()
        }
        null
    }

    fun size(): Int = lock.withLock { q.size }
}

/**
 * Bandwidth accounting / soft hibernation (C Tor `hibernate.c` lite).
 *
 * Tracks bytes read/written this interval; soft-hibernates when soft limit hit,
 * hard-hibernates when hard limit hit.
 */
class HibernateAccounting(
    var softLimitBytes: Long = 0,
    var hardLimitBytes: Long = 0,
    var intervalSec: Long = 30 * 24 * 3600,
) {
    enum class State { LIVE, SOFT, HARD }

    var bytesRead: Long = 0
        private set
    var bytesWritten: Long = 0
        private set
    var intervalStartedEpochSec: Long = System.currentTimeMillis() / 1000
        private set

    fun note(read: Long = 0, written: Long = 0) {
        bytesRead += read.coerceAtLeast(0)
        bytesWritten += written.coerceAtLeast(0)
    }

    fun total(): Long = bytesRead + bytesWritten

    fun state(nowEpochSec: Long = System.currentTimeMillis() / 1000): State {
        maybeReset(nowEpochSec)
        val t = total()
        if (hardLimitBytes > 0 && t >= hardLimitBytes) return State.HARD
        if (softLimitBytes > 0 && t >= softLimitBytes) return State.SOFT
        return State.LIVE
    }

    fun acceptsNewConnections(nowEpochSec: Long = System.currentTimeMillis() / 1000): Boolean =
        state(nowEpochSec) == State.LIVE

    fun acceptsData(nowEpochSec: Long = System.currentTimeMillis() / 1000): Boolean =
        state(nowEpochSec) != State.HARD

    private fun maybeReset(now: Long) {
        if (intervalSec <= 0) return
        if (now - intervalStartedEpochSec >= intervalSec) {
            bytesRead = 0
            bytesWritten = 0
            intervalStartedEpochSec = now
        }
    }
}

/**
 * Relay history / reputation counters (C Tor `rephist.c` lite).
 */
object RepHist {
    data class CircHist(
        var nCreated: Long = 0,
        var nSucceeded: Long = 0,
        var nFailed: Long = 0,
        var bytesRead: Long = 0,
        var bytesWritten: Long = 0,
    )

    private val byRelay = java.util.concurrent.ConcurrentHashMap<String, CircHist>()

    fun forRelay(fpHex: String): CircHist =
        byRelay.getOrPut(fpHex.lowercase()) { CircHist() }

    fun noteCreate(fpHex: String) {
        forRelay(fpHex).nCreated++
    }

    fun noteSuccess(fpHex: String) {
        forRelay(fpHex).nSucceeded++
    }

    fun noteFailure(fpHex: String) {
        forRelay(fpHex).nFailed++
    }

    fun noteBytes(fpHex: String, read: Long, written: Long) {
        val h = forRelay(fpHex)
        h.bytesRead += read
        h.bytesWritten += written
    }

    fun clear() = byRelay.clear()
}
