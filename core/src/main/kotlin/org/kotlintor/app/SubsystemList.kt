package org.kotlintor.app

/**
 * Subsystem list (C Tor `subsystem_list.c`).
 *
 * Inventory: `L1:app/main/subsystem_list.c`
 */
object SubsystemList {
    fun names(): List<String> = listOf(
        "mainloop",
        "or",
        "relay",
        "hs",
        "dirauth",
        "metrics",
        "dos",
        "conflux",
    )
}
