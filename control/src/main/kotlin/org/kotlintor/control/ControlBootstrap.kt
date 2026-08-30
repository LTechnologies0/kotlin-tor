package org.kotlintor.control

import org.kotlintor.BootstrapPhase
import org.kotlintor.BootstrapTracker

/**
 * Bootstrap STATUS_CLIENT lines (C Tor `control_bootstrap.c`).
 *
 * Inventory: `L1:feature/control/control_bootstrap.c`
 *
 * Phase machine: [BootstrapTracker] / [BootstrapPhase].
 */
object ControlBootstrap {
    fun starting(): BootstrapPhase = BootstrapPhase.STARTING

    fun done(): BootstrapPhase = BootstrapPhase.DONE

    fun statusLine(phase: BootstrapPhase, summary: String? = null): String =
        phase.statusLine(summary ?: phase.defaultSummary)

    fun tracker(onAdvance: ((String) -> Unit)? = null): BootstrapTracker =
        BootstrapTracker(onAdvance)

    fun progress(phase: BootstrapPhase): Int = phase.progress

    fun tag(phase: BootstrapPhase): String = phase.tagName
}
