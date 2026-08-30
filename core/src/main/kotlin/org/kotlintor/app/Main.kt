package org.kotlintor.app

/**
 * Process entry helpers (C Tor `main.c`).
 *
 * Inventory: `L1:app/main/main.c`
 *
 * Daemon ownership: [org.kotlintor.TorDaemon].
 */
object Main {
    const val SUBSYSTEM_LIST: String = "kotlin-tor-subsystems"

    fun subsystemNames(): List<String> = SubsystemList.names()
}
