package org.kotlintor.circuit

/**
 * Conflux subsystem (C Tor `conflux_sys.c`).
 *
 * Inventory: `L1:core/or/conflux_sys.c`
 */
object ConfluxSys {
    const val SUBSYS_NAME: String = "conflux"

    @Volatile private var enabled: Boolean = true

    fun initialize(enable: Boolean = true): Int {
        enabled = enable
        return 0
    }

    fun shutdown() {
        enabled = false
    }

    fun isEnabled(): Boolean = enabled

    fun newScheduler(set: ConfluxSet): ConfluxScheduler = ConfluxScheduler(set)
}
