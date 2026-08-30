package org.kotlintor.relay

import java.util.ArrayDeque
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * CREATE onion skin queue (C Tor `onion_queue.c`).
 *
 * Inventory: `L1:feature/relay/onion_queue.c`
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
