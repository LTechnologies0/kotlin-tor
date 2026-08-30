package org.kotlintor.relay

import org.kotlintor.config.ListenSpec
import org.kotlintor.config.TorConfig

/**
 * C Tor naming primary.
 *
 * Inventory: `L1:feature/relay/relay_config.c`
 */
data class RelayConfigView(
    val orPort: ListenSpec?,
    val dirPort: ListenSpec?,
    val nickname: String?,
    val contact: String?,
    val address: String?,
    val bridgeRelay: Boolean,
    val exitRelay: Boolean,
    val publishServerDescriptor: Boolean,
) {
    fun validate(): List<String> {
        val errs = mutableListOf<String>()
        if (orPort == null) errs += "ORPort required for relay"
        if (nickname != null && (nickname.length > 19 || !nickname.all { it.isLetterOrDigit() || it == '-' })) {
            errs += "Nickname invalid"
        }
        if (bridgeRelay && exitRelay) errs += "BridgeRelay and ExitRelay conflict"
        return errs
    }

    companion object {
        fun fromTorConfig(c: TorConfig): RelayConfigView =
            RelayConfigView(
                orPort = c.orPort,
                dirPort = c.dirPort,
                nickname = c.nickname,
                contact = c.contactInfo,
                address = c.address,
                bridgeRelay = c.bridgeRelay,
                exitRelay = c.exitRelay,
                publishServerDescriptor = c.publishServerDescriptor,
            )
    }
}
