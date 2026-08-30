package org.kotlintor.net

import java.util.concurrent.ConcurrentHashMap

/**
 * Address map (C Tor `addressmap.c`).
 *
 * Inventory: `L1:feature/client/addressmap.c`
 * L3 ops: `addressmap_*` / automap helpers via [AutomapAddressMap].
 */
object AddressMap {
    data class Mapping(
        val from: String,
        val to: String,
        val expiresEpochSec: Long = 0,
        val transient: Boolean = false,
        val trackExit: Boolean = false,
    )

    private val registry = ConcurrentHashMap<String, Mapping>()
    private val dnsFailures = ConcurrentHashMap<String, Int>()
    @Volatile private var initialized = false
    @Volatile private var virtualNetwork = "127.192.0.0/10"

    fun newAutomap(
        virtualNetworkCidr: String = "127.192.0.0/10",
        suffixes: List<String> = listOf(".onion", ".exit"),
    ): AutomapAddressMap {
        virtualNetwork = virtualNetworkCidr
        return AutomapAddressMap(virtualNetworkCidr, suffixes)
    }

    fun shouldAutomap(map: AutomapAddressMap, host: String): Boolean = map.shouldAutomap(host)

    /** C Tor `addressmap_address_should_automap`. */
    fun addressShouldAutomap(map: AutomapAddressMap, host: String): Boolean = shouldAutomap(map, host)

    fun getOrAssign(map: AutomapAddressMap, host: String): String = map.getOrAssign(host)

    fun reverse(map: AutomapAddressMap, ip: String): String? = map.reverse(ip)

    /** C Tor `addressmap_clear_mappings` / clean subset — drop all automap entries. */
    fun clear(map: AutomapAddressMap) = map.clear()

    /** C Tor `addressmap_clean` — same as clear for automap-only map. */
    fun clean(map: AutomapAddressMap) = map.clear()

    fun clearConfigured(map: AutomapAddressMap) = map.clear()

    /** C Tor `address_is_in_virtual_range`. */
    fun addressIsInVirtualRange(map: AutomapAddressMap, ip: String): Boolean =
        map.reverse(ip) != null || ip.startsWith("127.192.") || ip.startsWith("127.193.")

    /** C Tor `addressmap_init`. */
    fun addressmapInit() {
        initialized = true
        registry.clear()
        dnsFailures.clear()
    }

    /** C Tor `addressmap_free_all`. */
    fun addressmapFreeAll() {
        registry.clear()
        dnsFailures.clear()
        initialized = false
    }

    /** C Tor `addressmap_register`. */
    fun addressmapRegister(
        from: String,
        to: String,
        expiresEpochSec: Long = 0,
        transient: Boolean = false,
        trackExit: Boolean = false,
    ) {
        registry[from.lowercase()] = Mapping(from.lowercase(), to, expiresEpochSec, transient, trackExit)
    }

    /** C Tor `addressmap_register_virtual_address`. */
    fun addressmapRegisterVirtualAddress(map: AutomapAddressMap, host: String): String {
        val ip = map.getOrAssign(host)
        addressmapRegister(host, ip, transient = false)
        return ip
    }

    /** C Tor `addressmap_have_mapping`. */
    fun addressmapHaveMapping(host: String): Boolean =
        registry.containsKey(host.lowercase())

    /** C Tor `addressmap_get_mappings`. */
    fun addressmapGetMappings(): List<Mapping> = registry.values.toList()

    /** C Tor `addressmap_rewrite`. */
    fun addressmapRewrite(host: String): String =
        registry[host.lowercase()]?.to ?: host

    /** C Tor `addressmap_rewrite_reverse`. */
    fun addressmapRewriteReverse(ip: String): String? =
        registry.values.firstOrNull { it.to == ip }?.from

    /** C Tor `addressmap_clear_transient`. */
    fun addressmapClearTransient() {
        registry.entries.removeIf { it.value.transient }
    }

    /** C Tor `addressmap_clear_excluded_trackexithosts`. */
    fun addressmapClearExcludedTrackexithosts() {
        registry.entries.removeIf { it.value.trackExit }
    }

    /** C Tor `clear_trackexithost_mappings`. */
    fun clearTrackexithostMappings() = addressmapClearExcludedTrackexithosts()

    /** C Tor `addressmap_clear_invalid_automaps`. */
    fun addressmapClearInvalidAutomaps(map: AutomapAddressMap) {
        registry.entries.removeIf { (_, m) ->
            m.to.startsWith("127.") && map.reverse(m.to) == null && !addressIsInVirtualRange(map, m.to)
        }
    }

    /** C Tor `client_dns_set_addressmap`. */
    fun clientDnsSetAddressmap(hostname: String, address: String) {
        addressmapRegister(hostname, address, transient = true)
        dnsFailures.remove(hostname.lowercase())
    }

    /** C Tor `client_dns_set_reverse_addressmap`. */
    fun clientDnsSetReverseAddressmap(address: String, hostname: String) {
        addressmapRegister(address, hostname, transient = true)
    }

    /** C Tor `client_dns_incr_failures`. */
    fun clientDnsIncrFailures(hostname: String): Int {
        val k = hostname.lowercase()
        val n = (dnsFailures[k] ?: 0) + 1
        dnsFailures[k] = n
        return n
    }

    /** C Tor `client_dns_clear_failures`. */
    fun clientDnsClearFailures(hostname: String? = null) {
        if (hostname == null) dnsFailures.clear()
        else dnsFailures.remove(hostname.lowercase())
    }

    /** C Tor `parse_virtual_addr_network`. */
    fun parseVirtualAddrNetwork(cidr: String): Boolean {
        val parts = cidr.split('/', limit = 2)
        if (parts.size != 2) return false
        val plen = parts[1].toIntOrNull() ?: return false
        if (plen !in 8..30) return false
        return runCatching {
            java.net.InetAddress.getByName(parts[0])
            virtualNetwork = cidr
        }.isSuccess
    }

    /** C Tor `get_random_virtual_addr` — allocate via automap. */
    fun getRandomVirtualAddr(map: AutomapAddressMap, label: String = "virt"): String =
        map.getOrAssign("$label.exit")

    fun isInitialized(): Boolean = initialized
}
