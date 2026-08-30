package org.kotlintor.net.stack

import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.atomic.AtomicLong

/**
 * Onionmasq-class DNS fake-IP cookie maps.
 *
 * - IPv4 cookies in `10.0.0.0/8`
 * - IPv6 cookies in `fec0::/10` (legacy site-local; not globally routable)
 * - DNS response TTL = [ttlDnsSec] (60); cache lifespan = [ttlCacheSec] (70)
 * - Hard cap [maxEntries] per address family (DoS / memory bound)
 */
class FakeIpDnsCookies(
    val ttlDnsSec: Long = TIME_TO_LIVE_IN_DNS,
    val ttlCacheSec: Long = SECONDS_TO_LIVE_IN_CACHE,
    val maxEntries: Int = DEFAULT_MAX_ENTRIES,
) {
    data class Entry(val hostname: String, val expiresEpochMs: Long)

    private val v4 = ConcurrentHashMap<String, Entry>() // ip → host
    private val v4ByHost = ConcurrentHashMap<String, String>() // isolation|host → ip
    private val v6 = ConcurrentHashMap<String, Entry>()
    private val v6ByHost = ConcurrentHashMap<String, String>()
    private val clock = AtomicLong(0) // 0 = wall clock

    fun nowMs(): Long {
        val override = clock.get()
        return if (override > 0) override else System.currentTimeMillis()
    }

    /** Test hook. */
    fun advanceClockMs(ms: Long) {
        val base = nowMs()
        clock.set(base + ms)
    }

    fun makeForV4(hostname: String, isolationKey: Long? = null): String {
        val host = canonicalize(hostname)
        val mapKey = isoKey(isolationKey, host)
        v4ByHost[mapKey]?.let { ip ->
            val e = v4[ip]
            if (e != null && e.expiresEpochMs > nowMs()) return ip
        }
        flushExpired()
        enforceCap(v4, v4ByHost)
        var ip: String
        do {
            val b = ByteArray(4)
            b[0] = 10
            val rnd = ThreadLocalRandom.current()
            b[1] = rnd.nextInt(256).toByte()
            b[2] = rnd.nextInt(256).toByte()
            b[3] = rnd.nextInt(1, 255).toByte()
            ip = InetAddress.getByAddress(b).hostAddress
        } while (v4.containsKey(ip))
        val exp = nowMs() + ttlCacheSec * 1000L
        v4[ip] = Entry(host, exp)
        v4ByHost[mapKey] = ip
        return ip
    }

    fun makeForV6(hostname: String, isolationKey: Long? = null): String {
        val host = canonicalize(hostname)
        val mapKey = isoKey(isolationKey, host)
        v6ByHost[mapKey]?.let { ip ->
            val e = v6[ip]
            if (e != null && e.expiresEpochMs > nowMs()) return ip
        }
        flushExpired()
        enforceCap(v6, v6ByHost)
        val b = ByteArray(16)
        b[0] = 0xfe.toByte()
        b[1] = 0xc0.toByte()
        val rnd = ThreadLocalRandom.current()
        for (i in 2 until 16) b[i] = rnd.nextInt(256).toByte()
        val ip = InetAddress.getByAddress(b).hostAddress
        val exp = nowMs() + ttlCacheSec * 1000L
        v6[ip] = Entry(host, exp)
        v6ByHost[mapKey] = ip
        return ip
    }

    fun reverse(ip: String): String? {
        flushExpired()
        val key = normalizeIp(ip) ?: return null
        v4[key]?.let { if (it.expiresEpochMs > nowMs()) return it.hostname }
        v6[key]?.let { if (it.expiresEpochMs > nowMs()) return it.hostname }
        // Also try compressed IPv6 forms
        runCatching {
            val canon = InetAddress.getByName(ip).hostAddress
            v4[canon]?.takeIf { it.expiresEpochMs > nowMs() }?.hostname?.let { return it }
            v6[canon]?.takeIf { it.expiresEpochMs > nowMs() }?.hostname?.let { return it }
        }
        return null
    }

    fun isCookieIp(ip: String): Boolean {
        val a = runCatching { InetAddress.getByName(ip).address }.getOrNull() ?: return false
        return when (a.size) {
            4 -> a[0] == 10.toByte()
            16 -> a[0] == 0xfe.toByte() && (a[1].toInt() and 0xc0) == 0xc0
            else -> false
        }
    }

    fun clear() {
        v4.clear()
        v4ByHost.clear()
        v6.clear()
        v6ByHost.clear()
    }

    fun sizeV4(): Int = v4.size
    fun sizeV6(): Int = v6.size

    private fun flushExpired() {
        val now = nowMs()
        pruneExpired(v4, v4ByHost, now)
        pruneExpired(v6, v6ByHost, now)
    }

    private fun pruneExpired(
        byIp: ConcurrentHashMap<String, Entry>,
        byHost: ConcurrentHashMap<String, String>,
        now: Long,
    ) {
        val deadIps = mutableSetOf<String>()
        byIp.entries.removeIf {
            val dead = it.value.expiresEpochMs <= now
            if (dead) deadIps += it.key
            dead
        }
        if (deadIps.isNotEmpty()) {
            byHost.entries.removeIf { it.value in deadIps }
        }
    }

    /** Evict oldest by expiry until under [maxEntries] before insert. */
    private fun enforceCap(
        byIp: ConcurrentHashMap<String, Entry>,
        byHost: ConcurrentHashMap<String, String>,
    ) {
        val limit = maxEntries.coerceAtLeast(1)
        while (byIp.size >= limit) {
            val victim = byIp.entries.minByOrNull { it.value.expiresEpochMs } ?: break
            byIp.remove(victim.key)
            byHost.entries.removeIf { it.value == victim.key }
        }
    }

    companion object {
        const val TIME_TO_LIVE_IN_DNS = 60L
        const val SECONDS_TO_LIVE_IN_CACHE = 70L
        const val DEFAULT_MAX_ENTRIES = 8192
        /** Onionmasq fake resolver IPv4. */
        const val FAKE_RESOLVER_V4 = "169.254.42.53"
        const val FAKE_RESOLVER_V6 = "fe80::53:53"

        fun canonicalize(hostname: String): String {
            var h = hostname.trim().lowercase()
            while (h.endsWith('.')) h = h.dropLast(1)
            return h
        }

        private fun isoKey(isolationKey: Long?, host: String): String =
            "${isolationKey ?: 0}|$host"

        private fun normalizeIp(ip: String): String? =
            runCatching { InetAddress.getByName(ip).hostAddress }.getOrNull()
    }
}
