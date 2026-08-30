package org.kotlintor.relay

import org.kotlintor.config.TorConfig
import org.kotlintor.net.PrivateAddresses
import java.net.InetAddress

/**
 * C Tor naming primary.
 *
 * Inventory: `L1:feature/relay/relay_find_addr.c`
 */
object RelayFindAddr {
    /**
     * Prefer configured Address=, else first non-private NIC IPv4, else null.
     * C Tor `relay_find_addr_to_publish`.
     */
    fun addressToPublish(config: TorConfig): String? {
        config.address?.trim()?.takeIf { it.isNotEmpty() }?.let { return it }
        return runCatching {
            InetAddress.getAllByName(InetAddress.getLocalHost().hostName)
                .mapNotNull { it.hostAddress }
                .firstOrNull { !PrivateAddresses.isPrivate(it) && !it.contains(':') }
        }.getOrNull()
            ?: runCatching {
                NetworkInterfaceAddrs.firstPublicIpv4()
            }.getOrNull()
    }

    /** Prefer first public IPv6 for dual-stack advertisement (when present). */
    fun ipv6ToPublish(config: TorConfig): String? {
        val configured = config.address?.trim()?.takeIf { it.contains(':') }
        if (configured != null) return configured
        return NetworkInterfaceAddrs.firstPublicIpv6()
    }

    fun suggestAddresses(config: TorConfig): Pair<String?, String?> =
        addressToPublish(config) to ipv6ToPublish(config)
}
