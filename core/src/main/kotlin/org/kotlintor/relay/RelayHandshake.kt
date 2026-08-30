package org.kotlintor.relay

import org.kotlintor.config.TorConfig
import java.util.concurrent.CopyOnWriteArrayList

/**
 * C Tor naming primary.
 *
 * Inventory: `L1:feature/relay/relay_handshake.c`
 */
enum class RelayHandshakeState {
    NONE,
    VERSIONS,
    CERTS,
    AUTH_CHALLENGE,
    AUTHENTICATE,
    NETINFO,
    OPEN,
}

object RelayHandshake {
    private val recent = CopyOnWriteArrayList<RelayHandshakeState>()

    fun advertisedLinkVersions(config: TorConfig): List<Int> = listOf(3, 4, 5)

    fun supportsCreateFast(config: TorConfig): Boolean = true

    fun supportsNtor(config: TorConfig): Boolean = true

    fun noteState(state: RelayHandshakeState) {
        recent += state
        while (recent.size > 64) recent.removeAt(0)
    }

    fun lastStates(): List<RelayHandshakeState> = recent.toList()

    fun clear() = recent.clear()
}
