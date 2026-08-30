package org.kotlintor.pt

import java.util.concurrent.CopyOnWriteArrayList

/**
 * Bridge configuration helpers (C Tor `bridges.c`).
 *
 * Inventory: `L1:feature/client/bridges.c`
 */
object Bridges {
    private val configured = CopyOnWriteArrayList<BridgeLine>()
    private val marked = CopyOnWriteArrayList<BridgeLine>()
    private val learnedIds = mutableMapOf<String, ByteArray>()

    fun parseLine(line: String): BridgeLine? = BridgeLine.parse(line)

    fun isBridgeLine(line: String): Boolean = parseLine(line) != null

    fun transportName(line: BridgeLine): String = line.transport ?: "vanilla"

    fun countConfigured(lines: List<String>): Int = lines.count { isBridgeLine(it) }

    /** C Tor `bridge_add_from_config`. */
    fun bridgeAddFromConfig(line: String): BridgeLine? {
        val b = parseLine(line) ?: return null
        bridgeResolveConflicts(b)
        configured += b
        return b
    }

    /** C Tor `bridge_list_get`. */
    fun bridgeListGet(): List<BridgeLine> = configured.toList()

    /** C Tor `clear_bridge_list` / `bridges_free_all`. */
    fun clearBridgeList() {
        configured.clear()
        marked.clear()
        learnedIds.clear()
    }

    fun bridgesFreeAll() = clearBridgeList()

    /** C Tor `mark_bridge_list`. */
    fun markBridgeList() {
        marked.clear()
        marked.addAll(configured)
    }

    /** C Tor `bridge_resolve_conflicts` — drop prior same host:port. */
    fun bridgeResolveConflicts(bridge: BridgeLine) {
        configured.removeIf { it.host == bridge.host && it.port == bridge.port }
    }

    /** C Tor `addr_is_a_configured_bridge`. */
    fun addrIsAConfiguredBridge(host: String, port: Int): Boolean =
        configured.any { it.host.equals(host, true) && it.port == port }

    /** C Tor `node_is_a_configured_bridge` / `extend_info_is_a_configured_bridge`. */
    fun nodeIsAConfiguredBridge(fingerprintHex: String?): Boolean {
        if (fingerprintHex.isNullOrBlank()) return false
        val fp = fingerprintHex.filter { it != ' ' }.lowercase()
        return configured.any { it.fingerprintHex?.lowercase() == fp }
    }

    fun extendInfoIsAConfiguredBridge(fingerprintHex: String?): Boolean =
        nodeIsAConfiguredBridge(fingerprintHex)

    /** C Tor `bridge_get_addr_port`. */
    fun bridgeGetAddrPort(bridge: BridgeLine): Pair<String, Int> = bridge.host to bridge.port

    /** C Tor `bridge_get_rsa_id_digest`. */
    fun bridgeGetRsaIdDigest(bridge: BridgeLine): ByteArray? {
        val hex = bridge.fingerprintHex ?: return null
        if (hex.length < 40) return null
        return hex.chunked(2).take(20).map { it.toInt(16).toByte() }.toByteArray()
    }

    /** C Tor `bridget_get_transport_name` (C Tor typo preserved). */
    fun bridgetGetTransportName(bridge: BridgeLine): String = transportName(bridge)

    /** C Tor `bridge_has_invalid_transport`. */
    fun bridgeHasInvalidTransport(bridge: BridgeLine): Boolean {
        val t = bridge.transport ?: return false
        return t.isBlank() || t.any { !(it.isLetterOrDigit() || it == '_' || it == '-') }
    }

    /** C Tor `any_bridges_dont_support_microdescriptors`. */
    fun anyBridgesDontSupportMicrodescriptors(): Boolean =
        configured.any { it.transport != null && it.transport != "vanilla" }

    /** C Tor `find_bridge_by_digest`. */
    fun findBridgeByDigest(digestHex: String): BridgeLine? {
        val fp = digestHex.filter { it != ' ' }.lowercase()
        return configured.firstOrNull { it.fingerprintHex?.lowercase() == fp }
    }

    /** C Tor `get_configured_bridge_by_addr_port_digest`. */
    fun getConfiguredBridgeByAddrPortDigest(
        host: String,
        port: Int,
        digestHex: String? = null,
    ): BridgeLine? =
        configured.firstOrNull {
            it.host.equals(host, true) && it.port == port &&
                (digestHex == null || it.fingerprintHex?.equals(digestHex, true) == true)
        }

    fun getConfiguredBridgeByExactAddrPortDigest(
        host: String,
        port: Int,
        digestHex: String?,
    ): BridgeLine? = getConfiguredBridgeByAddrPortDigest(host, port, digestHex)

    fun getConfiguredBridgeByOrportsDigest(host: String, port: Int, digestHex: String?): BridgeLine? =
        getConfiguredBridgeByAddrPortDigest(host, port, digestHex)

    /** C Tor `find_transport_name_by_bridge_addrport`. */
    fun findTransportNameByBridgeAddrport(host: String, port: Int): String? =
        getConfiguredBridgeByAddrPortDigest(host, port)?.let { transportName(it) }

    /** C Tor `get_transport_by_bridge_addrport`. */
    fun getTransportByBridgeAddrport(host: String, port: Int): String? =
        findTransportNameByBridgeAddrport(host, port)

    /** C Tor `get_socks_args_by_bridge_addrport`. */
    fun getSocksArgsByBridgeAddrport(host: String, port: Int): Map<String, String> =
        getConfiguredBridgeByAddrPortDigest(host, port)?.args ?: emptyMap()

    /** C Tor `fetch_bridge_descriptors` — mark intent; returns count. */
    fun fetchBridgeDescriptors(): Int = configured.size

    /** C Tor `learned_bridge_descriptor`. */
    fun learnedBridgeDescriptor(fingerprintHex: String, identity: ByteArray) {
        learnedIds[fingerprintHex.lowercase()] = identity.copyOf()
    }

    /** C Tor `learned_router_identity`. */
    fun learnedRouterIdentity(digestHex: String, identity: ByteArray) =
        learnedBridgeDescriptor(digestHex, identity)

    /** C Tor `conflux_can_exclude_used_bridges`. */
    fun confluxCanExcludeUsedBridges(): Boolean = configured.isNotEmpty()
}
