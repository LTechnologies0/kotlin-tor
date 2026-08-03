package org.kotlintor.relay

import org.kotlintor.config.TorConfig

/**
 * Relay vs client mode helpers (C Tor `routermode.c`).
 *
 * Inventory: `L1:feature/relay/routermode.c`
 */
object RouterMode {
    @Volatile
    private var advertisedOverride: Boolean? = null

    /** True when we run an OR listener (not ClientOnly). */
    fun serverMode(config: TorConfig): Boolean = config.isRelay

    /** True when we are a public OR (ORPort set, not bridge-only hide). */
    fun publicServerMode(config: TorConfig): Boolean =
        serverMode(config) && !config.bridgeRelay

    /** True when we should publish a server descriptor. */
    fun advertisedServerMode(config: TorConfig): Boolean {
        advertisedOverride?.let { return it }
        return serverMode(config) && (config.publishServerDescriptor || config.orPort != null)
    }

    /** Directory authority / bridge-authority mode. */
    fun dirServerMode(config: TorConfig): Boolean =
        config.authoritativeDirectory || config.bridgeAuthoritativeDir

    /** Exit capability advertised (ExitRelay and policy not reject-all). */
    fun exitMode(config: TorConfig): Boolean =
        serverMode(config) && config.exitRelay

    /** C Tor `router_set_advertised_server_mode` analogue for tests / control. */
    fun setAdvertisedServerMode(value: Boolean?) {
        advertisedOverride = value
    }

    fun summary(config: TorConfig): String = buildString {
        append("clientOnly=").append(config.clientOnly)
        append(" server=").append(serverMode(config))
        append(" public=").append(publicServerMode(config))
        append(" advertised=").append(advertisedServerMode(config))
        append(" dirauth=").append(dirServerMode(config))
        append(" exit=").append(exitMode(config))
        append(" bridge=").append(config.bridgeRelay)
    }
}
