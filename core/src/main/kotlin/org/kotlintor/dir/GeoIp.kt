package org.kotlintor.dir

import java.net.InetAddress

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
