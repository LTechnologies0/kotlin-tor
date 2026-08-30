package org.kotlintor.relay

import org.kotlintor.net.PrivateAddresses

internal object NetworkInterfaceAddrs {
    fun firstPublicIpv4(): String? {
        val ifaces = java.net.NetworkInterface.getNetworkInterfaces() ?: return null
        for (ni in ifaces) {
            if (!ni.isUp || ni.isLoopback) continue
            for (addr in ni.inetAddresses) {
                val h = addr.hostAddress ?: continue
                if (h.contains(':') || h.contains('%')) continue
                if (!PrivateAddresses.isPrivate(h)) return h
            }
        }
        return null
    }

    fun firstPublicIpv6(): String? {
        val ifaces = java.net.NetworkInterface.getNetworkInterfaces() ?: return null
        for (ni in ifaces) {
            if (!ni.isUp || ni.isLoopback) continue
            for (addr in ni.inetAddresses) {
                var h = addr.hostAddress ?: continue
                if (!h.contains(':')) continue
                if (h.contains('%')) h = h.substringBefore('%')
                if (h.startsWith("fe80", ignoreCase = true)) continue
                if (PrivateAddresses.isPrivate(h)) continue
                return h
            }
        }
        return null
    }
}
