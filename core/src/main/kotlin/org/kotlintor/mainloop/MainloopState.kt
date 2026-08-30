package org.kotlintor.mainloop

/**
 * Mainloop runtime state mirror (C Tor `mainloop_state_t`).
 *
 * Inventory: `L2:core/mainloop/mainloop_state_t`
 *
 * Lifecycle: [MainloopSys] / [org.kotlintor.TorDaemon].
 */
data class MainloopState(
    val started: Boolean = false,
    val netDisabled: Boolean = false,
    val tickCount: Long = 0,
)
