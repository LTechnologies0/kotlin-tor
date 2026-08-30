package org.kotlintor.stats

import java.util.concurrent.ConcurrentHashMap

/**
 * OR connection byte stats (C Tor `connstats.c`).
 *
 * Inventory: `L1:feature/stats/connstats.c`
 */
object ConnStats {
    data class ConnBytes(var read: Long = 0, var written: Long = 0, var ipv6: Boolean = false)

    @Volatile
    var enabled: Boolean = true

    private val byId = ConcurrentHashMap<Long, ConnBytes>()
    private var startedEpochSec: Long = System.currentTimeMillis() / 1000

    fun init(nowEpochSec: Long = System.currentTimeMillis() / 1000) {
        startedEpochSec = nowEpochSec
        byId.clear()
    }

    fun noteOrConnBytes(
        connId: Long,
        numRead: Long,
        numWritten: Long,
        whenEpochSec: Long = System.currentTimeMillis() / 1000,
        isIpv6: Boolean = false,
    ) {
        if (!enabled) return
        val c = byId.getOrPut(connId) { ConnBytes(ipv6 = isIpv6) }
        c.read += numRead.coerceAtLeast(0)
        c.written += numWritten.coerceAtLeast(0)
        c.ipv6 = isIpv6
    }

    fun reset(nowEpochSec: Long = System.currentTimeMillis() / 1000) {
        byId.clear()
        startedEpochSec = nowEpochSec
    }

    fun format(nowEpochSec: Long = System.currentTimeMillis() / 1000): String {
        val totalR = byId.values.sumOf { it.read }
        val totalW = byId.values.sumOf { it.written }
        val v6 = byId.values.count { it.ipv6 }
        return buildString {
            appendLine("conn-stats-end $nowEpochSec (${nowEpochSec - startedEpochSec} s)")
            appendLine("conn-bi-direct $totalR,$totalW,${byId.size},$v6")
        }
    }

    fun terminate() = byId.clear()
}
