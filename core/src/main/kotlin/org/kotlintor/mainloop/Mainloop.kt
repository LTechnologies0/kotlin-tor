package org.kotlintor.mainloop

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Mainloop run control (C Tor `mainloop.c`).
 *
 * Inventory: `L1:core/mainloop/mainloop.c`
 */
object Mainloop {
    private val running = AtomicBoolean(false)
    private val ticks = AtomicLong(0)
    private val lastTickMs = AtomicLong(0)

    fun start(): Int {
        running.set(true)
        lastTickMs.set(System.currentTimeMillis())
        return 0
    }

    fun stop() {
        running.set(false)
    }

    fun isRunning(): Boolean = running.get()

    fun tick(): Long {
        if (!running.get()) return ticks.get()
        ticks.incrementAndGet()
        lastTickMs.set(System.currentTimeMillis())
        return ticks.get()
    }

    fun tickCount(): Long = ticks.get()

    fun lastTickMs(): Long = lastTickMs.get()
}
