package org.kotlintor.dir

import org.kotlintor.config.TorConfig
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Dirauth periodic event catalog (C Tor `dirauth_periodic.c`).
 *
 * Inventory: `L1:feature/dirauth/dirauth_periodic.c`
 */
object DirAuthPeriodic {
    private val registered = AtomicBoolean(false)

    fun scheduleHints(config: TorConfig): Map<String, Long> {
        val t = DirAuthSys.timingFromConfig(config)
        return mapOf(
            "vote_interval_sec" to t.voteIntervalSec.toLong(),
            "vote_delay_sec" to t.voteSeconds.toLong(),
            "dist_delay_sec" to t.distSeconds.toLong(),
            "check_descriptor_sec" to 60L,
        )
    }

    /** C Tor `dirauth_register_periodic_events`. */
    fun dirauthRegisterPeriodicEvents(config: TorConfig? = null): Int {
        registered.set(true)
        if (config != null) scheduleHints(config)
        return 0
    }

    fun isRegistered(): Boolean = registered.get()

    fun clearRegistration() {
        registered.set(false)
    }

    /** C Tor `reschedule_dirvote`. */
    fun rescheduleDirvote(config: TorConfig? = null): Int {
        registered.set(true)
        if (config != null) scheduleHints(config)
        return 0
    }
}
