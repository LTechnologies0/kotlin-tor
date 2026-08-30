package org.kotlintor.relay

import org.kotlintor.config.TorConfig

/**
 * Relay vs client mode helpers (C Tor `routermode.c` / `routermode.h`).
 *
 * Inventory: `L1:feature/relay/routermode.c`
 */
object RouterMode {
    /**
     * C Tor `server_is_advertised` — whether we have published our descriptor lately.
     * Independent of config; controlled by [setServerAdvertised].
     */
    @Volatile
    private var serverIsAdvertised: Boolean = false

    /** Optional test override for [advertisedServerMode]; null = use [serverIsAdvertised]. */
    @Volatile
    private var advertisedOverride: Boolean? = null

    /**
     * C Tor `server_mode` — ClientOnly=0 and ORPort set.
     */
    fun serverMode(config: TorConfig): Boolean =
        !config.clientOnly && config.orPort != null

    /**
     * C Tor `public_server_mode` — server and not BridgeRelay.
     */
    fun publicServerMode(config: TorConfig): Boolean =
        serverMode(config) && !config.bridgeRelay

    /**
     * C Tor `advertised_server_mode` — global publish latch (not derived from config).
     */
    fun advertisedServerMode(): Boolean = advertisedOverride ?: serverIsAdvertised

    /**
     * Config-aware helper used by kotlin-tor callers that historically passed [config].
     * Prefer [advertisedServerMode] for C Tor parity; this returns the latch unless
     * an override is set, and does not re-derive from PublishServerDescriptor.
     */
    fun advertisedServerMode(config: TorConfig): Boolean {
        advertisedOverride?.let { return it }
        return advertisedServerMode()
    }

    /**
     * C Tor `set_server_advertised`.
     */
    fun setServerAdvertised(advertised: Boolean) {
        serverIsAdvertised = advertised
    }

    /** Alias kept for existing call sites. */
    fun setAdvertisedServerMode(value: Boolean?) {
        if (value == null) {
            advertisedOverride = null
        } else {
            advertisedOverride = value
            serverIsAdvertised = value
        }
    }

    /**
     * C Tor `dir_server_mode` —
     * DirCache enabled and (DirPort set OR (server_mode && bandwidth OK)).
     * Also true for configured directory authorities (kotlin-tor / dirauth path).
     */
    fun dirServerMode(
        config: TorConfig,
        hasBandwidthToBeDirserver: Boolean = true,
    ): Boolean {
        if (config.authoritativeDirectory || config.bridgeAuthoritativeDir) return true
        if (!config.runtime.dirCache) return false
        if (config.dirPort != null) return true
        return serverMode(config) && hasBandwidthToBeDirserver
    }

    /** Exit capability advertised (ExitRelay). Not in routermode.c; kotlin-tor convenience. */
    fun exitMode(config: TorConfig): Boolean =
        serverMode(config) && config.exitRelay

    fun summary(config: TorConfig): String = buildString {
        append("clientOnly=").append(config.clientOnly)
        append(" server=").append(serverMode(config))
        append(" public=").append(publicServerMode(config))
        append(" advertised=").append(advertisedServerMode())
        append(" dircache=").append(dirServerMode(config))
        append(" exit=").append(exitMode(config))
        append(" bridge=").append(config.bridgeRelay)
    }
}
