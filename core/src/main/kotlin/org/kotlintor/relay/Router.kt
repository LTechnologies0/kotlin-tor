package org.kotlintor.relay

import org.kotlintor.config.TorConfig

/**
 * Router / OR identity helpers (C Tor `router.c`).
 *
 * Inventory: `L1:feature/relay/router.c`
 */
object Router {
    fun serverMode(c: TorConfig): Boolean = RouterMode.serverMode(c)
    fun advertisedServerMode(c: TorConfig): Boolean = RouterMode.advertisedServerMode(c)
}
