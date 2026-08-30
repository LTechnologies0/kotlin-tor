package org.kotlintor.mainloop

import java.util.concurrent.atomic.AtomicBoolean

/**
 * Mainloop subsystem (C Tor `mainloop_sys.c`).
 *
 * Inventory: `L1:core/mainloop/mainloop_sys.c`
 */
object MainloopSys {
    const val SUBSYS_NAME: String = "mainloop"

    private val initialized = AtomicBoolean(false)

    fun initialize(): Int {
        if (!initialized.compareAndSet(false, true)) return 0
        Periodic.init()
        Mainloop.start()
        return 0
    }

    fun shutdown() {
        if (!initialized.compareAndSet(true, false)) return
        Mainloop.stop()
        Periodic.shutdown()
    }

    fun isInitialized(): Boolean = initialized.get()
}
