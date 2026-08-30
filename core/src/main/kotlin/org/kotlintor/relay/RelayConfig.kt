package org.kotlintor.relay

import org.kotlintor.config.TorConfig

/**
 * Relay config surface (C Tor `relay_config.c`).
 *
 * Inventory: `L1:feature/relay/relay_config.c`
 *
 * Typed view: [RelayConfigView].
 */
object RelayConfig {
    fun fromTorConfig(c: TorConfig): RelayConfigView = RelayConfigView.fromTorConfig(c)

    fun validate(c: TorConfig): List<String> = fromTorConfig(c).validate()
}
