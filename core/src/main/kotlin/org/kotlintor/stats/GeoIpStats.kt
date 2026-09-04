package org.kotlintor.stats

import org.kotlintor.dir.GeoIp
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * GeoIP client / directory request stats (C Tor `geoip_stats.c`).
 *
 * Inventory: `L1:feature/stats/geoip_stats.c`
 */
object GeoIpStats {
    enum class ClientAction { CONNECT, NETWORKSTATUS }
    enum class NsResponse {
        SUCCESS,
        REJECT_NOT_ENOUGH_SIGS,
        REJECT_UNAVAILABLE,
        REJECT_NOT_FOUND,
        REJECT_NOT_MODIFIED,
        REJECT_BUSY,
        SERVED,
    }
    enum class DirreqType { DIRECT, TUNNELED }
    enum class DirreqState {
        IS_FOR_NETWORK_STATUS,
        FLUSHING_DIR_CONN_FINISHED,
        END_CELL_SENT,
        CIRC_QUEUE_FLUSHED,
        CHANNEL_BUFFER_FLUSHED,
    }

    data class ClientSeen(
        val addr: String,
        val transport: String?,
        val action: ClientAction,
        var lastSeenEpochSec: Long,
    )

    @Volatile
    var entryEnabled: Boolean = false
    @Volatile
    var dirReqEnabled: Boolean = false

    private val clients = ConcurrentHashMap<String, ClientSeen>()
    private val nsResponses = ConcurrentHashMap<NsResponse, AtomicLong>()
    private val dirreqs = ConcurrentHashMap<Long, Pair<DirreqType, DirreqState>>()
    private var entryStarted: Long = System.currentTimeMillis() / 1000
    private var geoDb: GeoIp.Database? = null

    fun setGeoDb(db: GeoIp.Database?) {
        geoDb = db
    }

    fun noteClientSeen(
        action: ClientAction,
        addr: String,
        transportName: String? = null,
        nowEpochSec: Long = System.currentTimeMillis() / 1000,
    ) {
        if (!entryEnabled && action == ClientAction.CONNECT) return
        val key = "$action|$addr|${transportName ?: ""}"
        clients[key] = ClientSeen(addr, transportName, action, nowEpochSec)
    }

    fun removeOldClients(cutoffEpochSec: Long) {
        clients.entries.removeIf { it.value.lastSeenEpochSec < cutoffEpochSec }
    }

    fun noteNsResponse(response: NsResponse) {
        nsResponses.getOrPut(response) { AtomicLong(0) }.incrementAndGet()
    }

    fun startDirreq(dirreqId: Long, type: DirreqType = DirreqType.DIRECT) {
        if (!dirReqEnabled) return
        dirreqs[dirreqId] = type to DirreqState.IS_FOR_NETWORK_STATUS
    }

    fun changeDirreqState(dirreqId: Long, type: DirreqType, state: DirreqState) {
        if (!dirReqEnabled) return
        dirreqs[dirreqId] = type to state
    }

    fun getClientHistory(action: ClientAction): Map<String, Int> {
        val counts = LinkedHashMap<String, Int>()
        for (c in clients.values) {
            if (c.action != action) continue
            val cc = geoDb?.country(c.addr) ?: "??"
            counts[cc] = (counts[cc] ?: 0) + 1
        }
        return counts
    }

    fun formatEntryStats(nowEpochSec: Long = System.currentTimeMillis() / 1000): String {
        val hist = getClientHistory(ClientAction.CONNECT)
        return buildString {
            appendLine("entry-stats-end $nowEpochSec (${nowEpochSec - entryStarted} s)")
            appendLine("entry-ips ${hist.entries.joinToString(",") { "${it.key}=${it.value}" }}")
        }
    }

    fun formatBridgeStats(nowEpochSec: Long = System.currentTimeMillis() / 1000): String {
        val hist = getClientHistory(ClientAction.CONNECT)
        return buildString {
            appendLine("bridge-stats-end $nowEpochSec")
            appendLine("bridge-ips ${hist.entries.joinToString(",") { "${it.key}=${it.value}" }}")
        }
    }

    fun formatRequestHistory(): String =
        nsResponses.entries.joinToString(",") { "${it.key.name.lowercase()}=${it.value.get()}" }

    fun reset() {
        clients.clear()
        nsResponses.clear()
        dirreqs.clear()
        entryStarted = System.currentTimeMillis() / 1000
    }
}

/**
 * Naming primary for `geoip_stats.c` (STEM GeoipStats).
 *
 * Facade kept in this file so Windows CI does not hit a case-only filename clash
 * with [GeoIpStats] (`GeoIpStats.kt` vs `GeoipStats.kt`).
 */
object GeoipStats {
    fun entryEnabled(): Boolean = GeoIpStats.entryEnabled

    fun setEntryEnabled(v: Boolean) {
        GeoIpStats.entryEnabled = v
    }

    fun formatEntryStats(): String = GeoIpStats.formatEntryStats()
}
