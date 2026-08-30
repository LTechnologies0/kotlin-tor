package org.kotlintor.control

import org.kotlintor.BootstrapPhase
import org.kotlintor.BootstrapTracker

/**
 * Bootstrap tracker subsystem (C Tor `btrack.c`).
 *
 * Inventory: `L1:feature/control/btrack.c`
 *
 * ORCONN/CIRC event maps: [BtrackOrconn], [BtrackCircuit].
 */
object Btrack {
    fun newTracker(onAdvance: ((String) -> Unit)? = null): BootstrapTracker =
        BootstrapTracker(onAdvance)

    fun phases(): List<BootstrapPhase> = BootstrapPhase.entries.toList()

    fun advance(tracker: BootstrapTracker, to: BootstrapPhase, summary: String? = null) {
        tracker.advance(to, summary)
    }
}
