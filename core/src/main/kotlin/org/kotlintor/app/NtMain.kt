package org.kotlintor.app

/**
 * Windows NT service entry (C Tor `ntmain.c`) — JVM no-op mirror.
 *
 * Inventory: `L1:app/main/ntmain.c`
 */
object NtMain {
    fun serviceModeSupported(): Boolean = false
}
