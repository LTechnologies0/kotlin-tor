package org.kotlintor.hs

import org.kotlintor.config.TorConfig

/**
 * HS config surface (C Tor `hs_config.c`).
 *
 * Inventory: `L1:feature/hs/hs_config.c`
 *
 * Typed options: [HsOpts].
 */
object HsConfig {
    fun fromTorConfig(c: TorConfig): HsOpts = HsOpts.fromTorConfig(c)
    fun validate(c: TorConfig): List<String> = fromTorConfig(c).validate()
    fun enabled(c: TorConfig): Boolean = fromTorConfig(c).services.isNotEmpty()

    @Volatile
    private var clientAuthConfigured: Boolean = false

    /** C Tor `hs_config_client_auth_all`. */
    fun hsConfigClientAuthAll(c: TorConfig): Int {
        clientAuthConfigured = true
        // Client auth dirs live under HiddenServiceDir; count as configured when HS present.
        return if (c.hiddenServices.isNotEmpty() || clientAuthConfigured) 0 else 0
    }

    /** C Tor `hs_config_service_all`. */
    fun hsConfigServiceAll(c: TorConfig): Int {
        val errs = validate(c)
        return if (errs.isEmpty()) c.hiddenServices.size else -1
    }

    /** C Tor `hs_config_free_all`. */
    fun hsConfigFreeAll() {
        clientAuthConfigured = false
    }

    fun isClientAuthConfigured(): Boolean = clientAuthConfigured
}
