package org.kotlintor.app

import org.kotlintor.TorDaemon

/**
 * Ordered shutdown (C Tor `shutdown.c`).
 *
 * Inventory: `L1:app/main/shutdown.c`
 */
object Shutdown {
    fun stop(daemon: TorDaemon) = daemon.stop()
}
