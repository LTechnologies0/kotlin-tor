package org.kotlintor.net

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/**
 * Private / internal address checks (C Tor `tor_addr_is_internal` lite).
 *
 * Used by ExtendAllowPrivateAddresses / DirAllowPrivateAddresses / ClientRejectInternal.
 */
object PrivateAddresses {
    /**
     * True when [host] is an IPv4/IPv6 **literal** (no DNS). Hostnames return false
     * so ClientRejectInternalAddresses cannot leak via [InetAddress.getByName].
     */
    fun isIpLiteral(host: String): Boolean {
        val h = host.trim().removeSurrounding("[", "]")
        if (h.isEmpty()) return false
        if (h.any { it.isLetter() && it !in 'a'..'f' && it !in 'A'..'F' }) return false
        return looksIpv4(h) || looksIpv6(h)
    }

    fun isPrivateLiteral(host: String): Boolean {
        if (!isIpLiteral(host)) return false
        val h = host.trim().removeSurrounding("[", "]")
        return runCatching { isPrivate(InetAddress.getByName(h)) }.getOrDefault(true)
    }

    /** Only IP literals are classified; hostnames are not private (no DNS). */
    fun isPrivate(host: String): Boolean = isPrivateLiteral(host)

    private fun looksIpv4(h: String): Boolean {
        val p = h.split('.')
        if (p.size != 4) return false
        return p.all { part ->
            part.isNotEmpty() && part.all { it.isDigit() } && part.toIntOrNull() in 0..255
        }
    }

    private fun looksIpv6(h: String): Boolean = h.contains(':') && h.none { it == ' ' }

    fun isPrivate(addr: InetAddress): Boolean {
        if (addr.isAnyLocalAddress || addr.isLoopbackAddress || addr.isLinkLocalAddress) return true
        if (addr.isSiteLocalAddress) return true
        return when (addr) {
            is Inet4Address -> {
                val b = addr.address
                val a0 = b[0].toInt() and 0xff
                val a1 = b[1].toInt() and 0xff
                // 0.0.0.0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.168/16
                a0 == 0 || a0 == 10 || a0 == 127 ||
                    (a0 == 100 && a1 in 64..127) ||
                    (a0 == 169 && a1 == 254) ||
                    (a0 == 172 && a1 in 16..31) ||
                    (a0 == 192 && a1 == 168)
            }
            is Inet6Address -> {
                val b = addr.address
                // fc00::/7 unique local, fe80::/10 link-local already covered
                (b[0].toInt() and 0xfe) == 0xfc
            }
            else -> false
        }
    }

    /** True if [host] may be used as EXTEND target given [allowPrivate]. */
    fun allowExtend(host: String, allowPrivate: Boolean): Boolean =
        allowPrivate || !isPrivate(host)

    /** True if DirPort may serve [peer] given [allowPrivate]. */
    fun allowDirPeer(peer: InetAddress, allowPrivate: Boolean): Boolean =
        allowPrivate || !isPrivate(peer)
}
