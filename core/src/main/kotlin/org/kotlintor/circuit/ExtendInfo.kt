package org.kotlintor.circuit

import org.kotlintor.dir.RouterStatus
import org.kotlintor.net.PrivateAddresses
import org.kotlintor.util.hexToBytes
import java.net.InetAddress

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
    }

    fun supportsNtor(): Boolean = curve25519OnionKey != null && curve25519OnionKey.size == 32

    fun supportsNtorV3Flag(): Boolean = supportsNtor() && supportsNtorV3

    fun hasPreferredOnionKey(): Boolean = supportsNtor()

    fun hasOrPort(host: String, port: Int): Boolean =
        orPorts.any { it.host.equals(host, true) && it.port == port }

    fun addOrPort(host: String, port: Int): ExtendInfo {
        if (orPorts.size >= MAX_ADDRS) return this
        if (hasOrPort(host, port)) return this
        return copy(orPorts = orPorts + OrPort(host, port))
    }

    fun pickOrPort(): OrPort? = orPorts.firstOrNull { !it.isNull() }

    fun anyOrPortInternal(): Boolean =
        orPorts.any { !it.isNull() && PrivateAddresses.isPrivate(it.host) }

    fun fingerprintHex(): String =
        identityDigest.joinToString("") { b -> "%02X".format(b.toInt() and 0xff) }

    fun toHopKeys(): HopKeys? {
        val onion = curve25519OnionKey ?: return null
        return HopKeys(onion, edIdentity)
    }

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

        fun addrAllowed(host: String, allowPrivate: Boolean): Boolean {
            if (host.isEmpty()) return false
            if (allowPrivate) return true
            return !PrivateAddresses.isPrivate(host)
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
    }
}

/** Resolve whether an address string looks like a usable OR endpoint host. */
fun ExtendInfo.Companion.isLikelyIpOrHostname(host: String): Boolean {
    if (host.isEmpty()) return false
    return runCatching { InetAddress.getByName(host) }.isSuccess
}
