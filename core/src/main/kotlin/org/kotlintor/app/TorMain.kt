package org.kotlintor.app

import org.kotlintor.TorDaemon
import org.kotlintor.config.TorConfig

/**
 * Tor main orchestration (C Tor `tor_main.c`).
 *
 * Inventory: `L1:app/main/tor_main.c`
 */
object TorMain {
    fun createDaemon(config: TorConfig): TorDaemon = TorDaemon(config)
}
