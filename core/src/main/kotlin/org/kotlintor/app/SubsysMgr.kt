package org.kotlintor.app

/**
 * Subsystem manager (C Tor `subsysmgr.c`).
 *
 * Inventory: `L1:app/main/subsysmgr.c`
 */
object SubsysMgr {
    fun listed(): List<String> = SubsystemList.names()

    fun count(): Int = listed().size
}
