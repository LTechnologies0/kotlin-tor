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
    fun isPrivate(host: String): Boolean =
        runCatching { isPrivate(InetAddress.getByName(host)) }.getOrDefault(true)

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
        }
    }

    /** True if [host] may be used as EXTEND target given [allowPrivate]. */
    fun allowExtend(host: String, allowPrivate: Boolean): Boolean =
        allowPrivate || !isPrivate(host)

    /** True if DirPort may serve [peer] given [allowPrivate]. */
    fun allowDirPeer(peer: InetAddress, allowPrivate: Boolean): Boolean =
        allowPrivate || !isPrivate(peer)
}
