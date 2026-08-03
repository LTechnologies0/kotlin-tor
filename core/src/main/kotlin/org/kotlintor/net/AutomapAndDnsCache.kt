package org.kotlintor.net

import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * AutomapHostsOnResolve virtual address map (C Tor `addressmap.c` Automap subset).
 *
 * Maps hostnames (especially `.onion`) to addresses inside [virtualNetwork]
 * so local apps can connect via TransPort / DNSPort with a stable virtual IP.
 */
class AutomapAddressMap(
    val virtualNetworkCidr: String = "127.192.0.0/10",
    val suffixes: List<String> = listOf(".onion", ".exit"),
) {
    private val hostToIp = ConcurrentHashMap<String, String>()
    private val ipToHost = ConcurrentHashMap<String, String>()
    private val nextHostPart = AtomicInteger(1)
    private val network: Pair<ByteArray, Int>

    init {
        val (addr, plen) = virtualNetworkCidr.split('/', limit = 2)
        network = InetAddress.getByName(addr).address to plen.toInt()
    }

    fun shouldAutomap(host: String): Boolean {
        val h = host.lowercase()
        return suffixes.any { h.endsWith(it) }
    }

    fun getOrAssign(host: String): String {
        val key = host.lowercase()
        hostToIp[key]?.let { return it }
        synchronized(this) {
            hostToIp[key]?.let { return it }
            val ip = allocate()
            hostToIp[key] = ip
            ipToHost[ip] = key
            return ip
        }
    }

    fun reverse(ip: String): String? = ipToHost[ip]

    fun clear() {
        hostToIp.clear()
        ipToHost.clear()
        nextHostPart.set(1)
    }

    private fun allocate(): String {
        val (base, prefix) = network
        require(base.size == 4 && prefix in 8..30)
        val hostBits = 32 - prefix
        val maxHosts = (1 shl hostBits) - 2
        val n = nextHostPart.getAndIncrement()
        require(n <= maxHosts) { "virtual address space exhausted" }
        val baseInt = ((base[0].toInt() and 0xff) shl 24) or
            ((base[1].toInt() and 0xff) shl 16) or
            ((base[2].toInt() and 0xff) shl 8) or
            (base[3].toInt() and 0xff)
        val mask = -1 shl hostBits
        val ipInt = (baseInt and mask) or n
        return "%d.%d.%d.%d".format(
            (ipInt ushr 24) and 0xff,
            (ipInt ushr 16) and 0xff,
            (ipInt ushr 8) and 0xff,
            ipInt and 0xff,
        )
    }
}

/**
 * Exit DNS resolve cache (C Tor `dns.c` lite).
 */
class DnsResolveCache(
    private val ttlSec: Long = 300,
    private val maxEntries: Int = 4096,
) {
    data class Entry(val addrs: List<String>, val expiresEpochSec: Long)

    private val byName = ConcurrentHashMap<String, Entry>()

    fun get(hostname: String, nowEpochSec: Long = System.currentTimeMillis() / 1000): List<String>? {
        val e = byName[hostname.lowercase()] ?: return null
        if (nowEpochSec >= e.expiresEpochSec) {
            byName.remove(hostname.lowercase())
            return null
        }
        return e.addrs
    }

    fun put(hostname: String, addrs: List<String>, nowEpochSec: Long = System.currentTimeMillis() / 1000) {
        if (byName.size >= maxEntries) {
            val now = nowEpochSec
            byName.entries.removeIf { it.value.expiresEpochSec <= now }
            if (byName.size >= maxEntries) {
                byName.keys.take(maxEntries / 8).forEach { byName.remove(it) }
            }
        }
        byName[hostname.lowercase()] = Entry(addrs, nowEpochSec + ttlSec)
    }

    fun size(): Int = byName.size
    fun clear() = byName.clear()
}
