package org.kotlintor.stats

import java.util.concurrent.atomic.AtomicLong

/**
 * HS runtime stats (C Tor `hs_stats.c`).
 *
 * Inventory: `L1:feature/hs/hs_stats.c`
 */
object HsStats {
    @Volatile
    var enabled: Boolean = false

    private val introduce2 = AtomicLong(0)
    private val rendezvousLaunches = AtomicLong(0)

    fun noteIntroduce2Cell() {
        if (!enabled) return
        introduce2.incrementAndGet()
    }

    fun nIntroduce2V3Cells(): Long = introduce2.get()

    fun noteServiceRendezvousLaunch() {
        if (!enabled) return
        rendezvousLaunches.incrementAndGet()
    }

    fun nRendezvousLaunches(): Long = rendezvousLaunches.get()

    fun reset() {
        introduce2.set(0)
        rendezvousLaunches.set(0)
    }

    /** C Tor `hs_stats_note_introduce2_cell`. */
    fun hsStatsNoteIntroduce2Cell() {
        enabled = true
        noteIntroduce2Cell()
    }

    /** C Tor `hs_stats_get_n_introduce2_v3_cells`. */
    fun hsStatsGetNIntroduce2V3Cells(): Long = nIntroduce2V3Cells()

    /** C Tor `hs_stats_note_service_rendezvous_launch`. */
    fun hsStatsNoteServiceRendezvousLaunch() {
        enabled = true
        noteServiceRendezvousLaunch()
    }

    /** C Tor `hs_stats_get_n_rendezvous_launches`. */
    fun hsStatsGetNRendezvousLaunches(): Long = nRendezvousLaunches()
}
