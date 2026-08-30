package org.kotlintor.relay

import org.kotlintor.mainloop.Periodic

/**
 * OR / relay periodic events (C Tor `or_periodic.c`).
 *
 * Inventory: `L1:core/or/or_periodic.c`
 *
 * Registers relay-role events into [Periodic].
 */
object OrPeriodic {
    const val CHECK_DESCRIPTOR_INTERVAL_SEC: Int = 60
    const val CHECK_REACHABILITY_INTERVAL_SEC: Int = 300

    fun scheduleHints(): List<String> = listOf(
        "check_descriptor",
        "check_canonical_channels",
        "check_reachability",
        "write_stats_file",
    )

    /** Register default OR periodic items (idempotent). */
    fun registerDefaults() {
        Periodic.init()
        for (name in scheduleHints()) {
            val interval = when (name) {
                "check_descriptor" -> CHECK_DESCRIPTOR_INTERVAL_SEC
                "check_reachability" -> CHECK_REACHABILITY_INTERVAL_SEC
                else -> 60
            }
            Periodic.register(
                Periodic.EventItem(
                    name = name,
                    roles = Periodic.Role.ROUTER,
                    flags = Periodic.Flag.NEED_NET,
                    intervalSec = interval,
                ),
            )
        }
    }

    /** C Tor `or_register_periodic_events`. */
    fun orRegisterPeriodicEvents() = registerDefaults()

    fun runDue(nowSec: Long, netDisabled: Boolean = false): List<String> =
        Periodic.runDue(nowSec, Periodic.Role.ROUTER, netDisabled)
}
