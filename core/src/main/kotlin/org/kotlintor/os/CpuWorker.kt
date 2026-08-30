package org.kotlintor.os

import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * CPU worker / onionskin queue (C Tor `cpuworker.c`).
 *
 * Inventory: `L1:core/mainloop/cpuworker.c`
 *
 * JVM stand-in for C Tor workqueue: fixed thread pool for CREATE handshakes.
 */
object CpuWorker {
    enum class Priority { HIGH, LOW }

    private val initialized = AtomicBoolean(false)
    private val pool = AtomicReference<ExecutorService?>(null)
    private val nThreads = AtomicInteger(0)
    private val queued = AtomicInteger(0)
    private val completed = AtomicInteger(0)

    /** C Tor `cpuworker_init`. */
    fun init(threads: Int = 0): Int {
        if (!initialized.compareAndSet(false, true)) return 0
        val n = if (threads > 0) threads else Runtime.getRuntime().availableProcessors().coerceAtLeast(1)
        nThreads.set(n)
        pool.set(Executors.newFixedThreadPool(n) { r ->
            Thread(r, "ktor-cpuworker").apply { isDaemon = true }
        })
        queued.set(0)
        completed.set(0)
        return 0
    }

    /** C Tor `cpuworker_free_all`. */
    fun freeAll() {
        if (!initialized.compareAndSet(true, false)) return
        pool.getAndSet(null)?.shutdownNow()
        nThreads.set(0)
    }

    fun isInitialized(): Boolean = initialized.get()

    /** C Tor `cpuworker_get_n_threads`. */
    fun getNThreads(): Int = nThreads.get()

    fun queuedCount(): Int = queued.get()

    fun completedCount(): Int = completed.get()

    /** C Tor `cpuworker_queue_work` (simplified). */
    fun <T> queueWork(
        priority: Priority = Priority.HIGH,
        work: () -> T,
    ): Future<T>? {
        val ex = pool.get() ?: return null
        queued.incrementAndGet()
        return ex.submit(
            Callable {
                try {
                    work()
                } finally {
                    completed.incrementAndGet()
                }
            },
        )
    }

    /** Estimate μs for [n] onionskins of [type] (heuristic vs C Tor table). */
    fun estimatedUsecForOnionskins(n: Int, type: Int): Long {
        val per = when (type) {
            0x0001 /* FAST */ -> 50L
            0x0002 /* NTOR */ -> 400L
            0x0003 /* NTOR_V3 */ -> 500L
            else -> 300L
        }
        return n.coerceAtLeast(0) * per
    }
}
