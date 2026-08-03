package org.kotlintor.dir

import org.kotlintor.util.toHex
import java.net.InetAddress

/**
 * Router set language (C Tor `routerset_t` / `routerset.c`).
 *
 * Members: nicknames, `$hexid`, `fingerprint`, address/mask (`1.2.3.0/24`),
 * and `{cc}` country codes (requires [GeoIp] for country match).
 */
class RouterSet(description: String = "") {
    private val names = HashSet<String>()
    private val digests = HashSet<String>()
    private val countries = HashSet<String>()
    private val policies = ArrayList<AddrPolicy>()
    var description: String = description
        private set

    data class AddrPolicy(val network: ByteArray, val prefixLen: Int) {
        fun matches(ip: ByteArray): Boolean {
            if (ip.size != network.size) return false
            val full = prefixLen / 8
            val rem = prefixLen % 8
            for (i in 0 until full) if (ip[i] != network[i]) return false
            if (rem == 0) return true
            val mask = (0xff shl (8 - rem)) and 0xff
            return (ip[full].toInt() and mask) == (network[full].toInt() and mask)
        }
    }

    fun parse(s: String): RouterSet {
        for (tok in s.split(',').map { it.trim() }.filter { it.isNotEmpty() }) {
            when {
                tok.startsWith("{") && tok.endsWith("}") ->
                    countries += tok.substring(1, tok.length - 1).lowercase()
                tok.startsWith("$") ->
                    digests += tok.drop(1).lowercase().replace(" ", "")
                tok.contains('/') && tok[0].isDigit() -> {
                    val (addr, plen) = tok.split('/', limit = 2)
                    val ip = InetAddress.getByName(addr).address
                    policies += AddrPolicy(ip, plen.toInt())
                }
                tok.matches(Regex("[0-9A-Fa-f]{40}")) ->
                    digests += tok.lowercase()
                else -> names += tok.lowercase()
            }
        }
        return this
    }

    fun isEmpty(): Boolean =
        names.isEmpty() && digests.isEmpty() && countries.isEmpty() && policies.isEmpty()

    fun contains(
        nickname: String?,
        identityHex: String?,
        ip: String?,
        country: String? = null,
    ): Boolean {
        if (isEmpty()) return false
        if (nickname != null && nickname.lowercase() in names) return true
        if (identityHex != null && identityHex.lowercase().replace(" ", "") in digests) return true
        if (country != null && country.lowercase() in countries) return true
        if (ip != null && policies.isNotEmpty()) {
            val bytes = runCatching { InetAddress.getByName(ip).address }.getOrNull()
            if (bytes != null && policies.any { it.matches(bytes) }) return true
        }
        return false
    }

    fun containsRouter(rs: RouterStatus, country: String? = null): Boolean =
        contains(rs.nickname, rs.fingerprintHex, rs.ip, country)

    fun toSetString(): String = buildList {
        addAll(names)
        digests.forEach { add("\$$it") }
        countries.forEach { add("{$it}") }
        policies.forEach {
            val host = InetAddress.getByAddress(it.network).hostAddress
            add("$host/${it.prefixLen}")
        }
    }.joinToString(",")

    companion object {
        fun parse(s: String, description: String = ""): RouterSet =
            RouterSet(description).parse(s)
    }
}

/**
 * Directory download status / exponential backoff (C Tor `dlstatus.c`).
 */
class DownloadStatus(
    private val minDelaySec: Int = 10,
    private val maxDelaySec: Int = 3600,
    private val multiplier: Int = DIR_DEFAULT_RANDOM_MULTIPLIER,
) {
    var nFailures: Int = 0
        private set
    var nAttempts: Int = 0
        private set
    var nextAttemptAt: Long = 0
        private set
    var impossible: Boolean = false
        private set
    private var lastDelaySec: Int = minDelaySec

    fun reset() {
        nFailures = 0
        nAttempts = 0
        nextAttemptAt = 0
        impossible = false
        lastDelaySec = minDelaySec
    }

    fun markImpossible() {
        impossible = true
        nextAttemptAt = Long.MAX_VALUE / 4
    }

    fun isReady(nowEpochSec: Long = System.currentTimeMillis() / 1000): Boolean =
        !impossible && nowEpochSec >= nextAttemptAt

    fun incrementAttempt(nowEpochSec: Long = System.currentTimeMillis() / 1000): Long {
        nAttempts++
        return schedule(nowEpochSec)
    }

    fun incrementFailure(nowEpochSec: Long = System.currentTimeMillis() / 1000): Long {
        nFailures++
        return schedule(nowEpochSec)
    }

    private fun schedule(now: Long): Long {
        val high = (lastDelaySec * (multiplier + 1)).coerceAtMost(maxDelaySec)
        val low = lastDelaySec.coerceAtLeast(minDelaySec)
        val delay = if (high <= low) low else low + org.kotlintor.util.SecureRandomSource.nextInt(high - low + 1)
        lastDelaySec = delay.coerceIn(minDelaySec, maxDelaySec)
        nextAttemptAt = now + lastDelaySec
        return nextAttemptAt
    }

    companion object {
        const val DIR_DEFAULT_RANDOM_MULTIPLIER: Int = 3
        const val DIR_TEST_NET_RANDOM_MULTIPLIER: Int = 2
    }
}

/**
 * GeoIP country lookup (C Tor `lib/geoip`) — CIDR map loader.
 */
object GeoIp {
    data class Range(val start: Long, val end: Long, val cc: String)

    class Database(private val ranges: List<Range>) {
        fun country(ip: String): String? {
            val addr = runCatching { InetAddress.getByName(ip).address }.getOrNull() ?: return null
            if (addr.size != 4) return null
            var v = 0L
            for (b in addr) v = (v shl 8) or (b.toInt() and 0xff).toLong()
            // ranges sorted by start; linear scan is fine for lite DB; binary for large.
            var lo = 0
            var hi = ranges.size - 1
            while (lo <= hi) {
                val mid = (lo + hi) ushr 1
                val r = ranges[mid]
                when {
                    v < r.start -> hi = mid - 1
                    v > r.end -> lo = mid + 1
                    else -> return r.cc
                }
            }
            return null
        }
    }

    /** Parse Tor GeoIP format lines: `a,b,cc` (inclusive IPv4 integers). */
    fun parseTorFormat(text: String): Database {
        val ranges = text.lineSequence().mapNotNull { line ->
            val t = line.trim()
            if (t.isEmpty() || t.startsWith("#")) return@mapNotNull null
            val p = t.split(',')
            if (p.size < 3) return@mapNotNull null
            Range(p[0].toLong(), p[1].toLong(), p[2].lowercase())
        }.sortedBy { it.start }.toList()
        return Database(ranges)
    }
}
