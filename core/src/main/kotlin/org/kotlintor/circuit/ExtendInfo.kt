package org.kotlintor.circuit

import org.kotlintor.dir.RouterStatus
import org.kotlintor.net.PrivateAddresses
import org.kotlintor.util.hexToBytes
import java.net.InetAddress
import java.net.Inet6Address
import kotlin.random.Random

/**
 * Circuit extend hop info (C Tor `extend_info_t` / `extendinfo.c`).
 *
 * Inventory: `L1:core/or/extendinfo.c`, `L2:core/or/extend_info_t`
 */
data class ExtendInfo(
    val nickname: String = "",
    /** SHA1 RSA identity digest (20 bytes). */
    val identityDigest: ByteArray,
    /** Ed25519 identity (32 bytes) or null. */
    val edIdentity: ByteArray? = null,
    /** Up to [MAX_ADDRS] ORPort endpoints. */
    val orPorts: List<OrPort> = emptyList(),
    /** Curve25519 ntor onion key (32 bytes) or null for one-hop dir. */
    val curve25519OnionKey: ByteArray? = null,
    val supportsNtorV3: Boolean = false,
    val exitSupportsCongestionControl: Boolean = false,
    val enableCgo: Boolean = false,
) {
    data class OrPort(val host: String, val port: Int) {
        fun isNull(): Boolean = host.isEmpty() || port <= 0

        fun family(): Int = when {
            isNull() -> AF_UNSPEC
            runCatching { InetAddress.getByName(host) }.getOrNull() is Inet6Address -> AF_INET6
            else -> AF_INET
        }
    }

    /** C Tor `extend_info_supports_ntor` — key present and not all-zero. */
    fun supportsNtor(): Boolean {
        val k = curve25519OnionKey ?: return false
        if (k.size != 32) return false
        return k.any { it != 0.toByte() }
    }

    fun supportsNtorV3Flag(): Boolean = supportsNtor() && supportsNtorV3

    fun hasPreferredOnionKey(): Boolean = supportsNtor()

    fun hasOrPort(host: String, port: Int): Boolean =
        orPorts.any { it.host.equals(host, true) && it.port == port }

    /**
     * C Tor `extend_info_add_orport` — returns false when full ([MAX_ADDRS]).
     */
    fun tryAddOrPort(host: String, port: Int): Pair<ExtendInfo, Boolean> {
        if (orPorts.size >= MAX_ADDRS) return this to false
        if (hasOrPort(host, port)) return this to true
        return copy(orPorts = orPorts + OrPort(host, port)) to true
    }

    fun addOrPort(host: String, port: Int): ExtendInfo = tryAddOrPort(host, port).first

    /** Prefer first listed ORPort (client / non-server pick). */
    fun pickOrPort(): OrPort? = orPorts.firstOrNull { !it.isNull() }

    /**
     * C Tor `extend_info_pick_orport` for relay mode: random among IPv4
     * (and IPv6 when [ipv6Ok]). Clients use first entry.
     */
    fun pickOrPort(
        serverMode: Boolean,
        ipv6Ok: Boolean = true,
        rng: Random = Random.Default,
    ): OrPort? {
        if (!serverMode) return pickOrPort()
        val usable = orPorts.filter { p ->
            if (p.isNull()) return@filter false
            when (p.family()) {
                AF_INET -> true
                AF_INET6 -> ipv6Ok
                else -> false
            }
        }
        if (usable.isEmpty()) return null
        return usable[rng.nextInt(usable.size)]
    }

    /** C Tor `extend_info_get_orport` — first ORPort of [family] (`AF_INET`/`AF_INET6`). */
    fun getOrPort(family: Int): OrPort? =
        orPorts.firstOrNull { !it.isNull() && it.family() == family }

    fun anyOrPortInternal(): Boolean =
        orPorts.any { !it.isNull() && PrivateAddresses.isPrivate(it.host) }

    fun fingerprintHex(): String =
        identityDigest.joinToString("") { b -> "%02X".format(b.toInt() and 0xff) }

    fun toHopKeys(): HopKeys? {
        if (!supportsNtor()) return null
        val onion = curve25519OnionKey ?: return null
        return HopKeys(onion, edIdentity)
    }

    /** C Tor `extend_info_dup`. */
    fun dup(): ExtendInfo = copy(
        identityDigest = identityDigest.copyOf(),
        edIdentity = edIdentity?.copyOf(),
        curve25519OnionKey = curve25519OnionKey?.copyOf(),
        orPorts = orPorts.toList(),
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ExtendInfo) return false
        return identityDigest.contentEquals(other.identityDigest) &&
            (edIdentity?.contentEquals(other.edIdentity) ?: (other.edIdentity == null)) &&
            nickname == other.nickname &&
            orPorts == other.orPorts &&
            (curve25519OnionKey?.contentEquals(other.curve25519OnionKey)
                ?: (other.curve25519OnionKey == null)) &&
            supportsNtorV3 == other.supportsNtorV3 &&
            exitSupportsCongestionControl == other.exitSupportsCongestionControl &&
            enableCgo == other.enableCgo
    }

    override fun hashCode(): Int = identityDigest.contentHashCode()

    companion object {
        const val MAX_ADDRS: Int = 2
        const val AF_UNSPEC: Int = 0
        const val AF_INET: Int = 2
        const val AF_INET6: Int = 10

        /**
         * C Tor `extend_info_addr_is_allowed` — reject private/multicast unless
         * [allowPrivate].
         */
        fun addrAllowed(host: String, allowPrivate: Boolean): Boolean {
            if (host.isEmpty()) return false
            if (allowPrivate) return true
            if (PrivateAddresses.isPrivate(host)) return false
            val addr = runCatching { InetAddress.getByName(host) }.getOrNull() ?: return false
            return !addr.isMulticastAddress
        }

        private fun digest20(id: ByteArray, fingerprintHex: String): ByteArray =
            when {
                id.size >= 20 -> id.copyOf(20)
                else -> hexToBytes(fingerprintHex).let { if (it.size >= 20) it.copyOf(20) else it }
            }

        fun fromRouterStatus(
            rs: RouterStatus,
            onionKey: ByteArray? = rs.ntorOnionKey,
            edIdentity: ByteArray? = rs.ed25519Identity,
            supportsNtorV3: Boolean = rs.supportsNtorV3(),
            enableCgo: Boolean = false,
            asExitWithCc: Boolean = false,
        ): ExtendInfo =
            ExtendInfo(
                nickname = rs.nickname,
                identityDigest = digest20(rs.identity, rs.fingerprintHex),
                edIdentity = edIdentity,
                orPorts = listOf(OrPort(rs.ip, rs.orPort)),
                curve25519OnionKey = onionKey,
                supportsNtorV3 = supportsNtorV3,
                exitSupportsCongestionControl = asExitWithCc && supportsNtorV3,
                enableCgo = enableCgo,
            )

        /**
         * C Tor `extend_info_from_node` ntor gate — null when no usable ntor key.
         */
        fun fromRouterStatusRequiringNtor(
            rs: RouterStatus,
            onionKey: ByteArray? = rs.ntorOnionKey,
            edIdentity: ByteArray? = rs.ed25519Identity,
            supportsNtorV3: Boolean = rs.supportsNtorV3(),
            enableCgo: Boolean = false,
            asExitWithCc: Boolean = false,
        ): ExtendInfo? {
            val onion = onionKey
            if (onion == null || onion.size != 32 || onion.all { it == 0.toByte() }) return null
            return fromRouterStatus(
                rs, onion, edIdentity, supportsNtorV3, enableCgo, asExitWithCc,
            )
        }

        fun fromHop(
            nickname: String,
            fingerprintHex: String,
            host: String,
            port: Int,
            keys: HopKeys,
            supportsNtorV3: Boolean = false,
            enableCgo: Boolean = false,
        ): ExtendInfo =
            ExtendInfo(
                nickname = nickname,
                identityDigest = hexToBytes(fingerprintHex).let { if (it.size >= 20) it.copyOf(20) else it },
                edIdentity = keys.ed25519Identity,
                orPorts = listOf(OrPort(host, port)),
                curve25519OnionKey = keys.ntorOnionKey,
                supportsNtorV3 = supportsNtorV3,
                enableCgo = enableCgo,
            )

        /** Compact node conversion string (C Tor extend_info_describe analogue). */
        fun describe(ei: ExtendInfo): String =
            "${ei.nickname}/${ei.fingerprintHex()}@${ei.pickOrPort()?.host ?: "?"}:${ei.pickOrPort()?.port ?: 0}"

        /** C Tor `extend_info_new`. */
        fun extendInfoNew(
            nickname: String = "",
            identityDigest: ByteArray = ByteArray(20),
            orPort: OrPort? = null,
            curve25519OnionKey: ByteArray? = null,
            edIdentity: ByteArray? = null,
            supportsNtorV3: Boolean = false,
        ): ExtendInfo = ExtendInfo(
            nickname = nickname,
            identityDigest = identityDigest,
            edIdentity = edIdentity,
            orPorts = listOfNotNull(orPort),
            curve25519OnionKey = curve25519OnionKey,
            supportsNtorV3 = supportsNtorV3,
        )

        /** C Tor `extend_info_free_` — GC no-op; returns null for C free idiom. */
        fun extendInfoFree_(info: ExtendInfo?): ExtendInfo? = null

        /** C Tor `extend_info_dup`. */
        fun extendInfoDup(info: ExtendInfo): ExtendInfo = info.dup()

        /** C Tor `extend_info_add_orport`. */
        fun extendInfoAddOrport(info: ExtendInfo, host: String, port: Int): ExtendInfo =
            info.addOrPort(host, port)

        /** C Tor `extend_info_addr_is_allowed`. */
        fun extendInfoAddrIsAllowed(host: String, allowPrivate: Boolean): Boolean =
            addrAllowed(host, allowPrivate)

        /** C Tor `extend_info_any_orport_addr_is_internal`. */
        fun extendInfoAnyOrportAddrIsInternal(info: ExtendInfo): Boolean =
            info.anyOrPortInternal()

        /** C Tor `extend_info_from_node`. */
        fun extendInfoFromNode(rs: RouterStatus, onionKey: ByteArray? = rs.ntorOnionKey): ExtendInfo? =
            fromRouterStatusRequiringNtor(rs, onionKey)

        /** C Tor `extend_info_get_orport`. */
        fun extendInfoGetOrport(info: ExtendInfo, family: Int): OrPort? = info.getOrPort(family)

        /** C Tor `extend_info_has_orport`. */
        fun extendInfoHasOrport(info: ExtendInfo, host: String, port: Int): Boolean =
            info.hasOrPort(host, port)

        /** C Tor `extend_info_has_preferred_onion_key`. */
        fun extendInfoHasPreferredOnionKey(info: ExtendInfo): Boolean = info.hasPreferredOnionKey()

        /** C Tor `extend_info_pick_orport`. */
        fun extendInfoPickOrport(info: ExtendInfo, serverMode: Boolean = false): OrPort? =
            info.pickOrPort(serverMode)

        /** C Tor `extend_info_supports_ntor`. */
        fun extendInfoSupportsNtor(info: ExtendInfo): Boolean = info.supportsNtor()

        /** C Tor `extend_info_supports_ntor_v3`. */
        fun extendInfoSupportsNtorV3(info: ExtendInfo): Boolean = info.supportsNtorV3Flag()
    }
}

/** Resolve whether an address string looks like a usable OR endpoint host. */
fun ExtendInfo.Companion.isLikelyIpOrHostname(host: String): Boolean {
    if (host.isEmpty()) return false
    return runCatching { InetAddress.getByName(host) }.isSuccess
}
