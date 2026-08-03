package org.kotlintor.stats

import org.kotlintor.dir.GeoIp
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * OR connection byte stats (C Tor `connstats.c` lite).
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

/**
 * GeoIP client / directory request stats (C Tor `geoip_stats.c` lite).
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
 * Onion service host statistics (C Tor `hs_stats.c`).
 */
object HsStats {
    @Volatile
    var enabled: Boolean = false

    private val introduce2 = AtomicLong(0)
    private val rendezvousLaunches = AtomicLong(0)

    fun noteIntroduce2Cell() {
        if (!enabled) return
        introduce2.incrementAndGet()
    }

    fun nIntroduce2V3Cells(): Long = introduce2.get()

    fun noteServiceRendezvousLaunch() {
        if (!enabled) return
        rendezvousLaunches.incrementAndGet()
    }

    fun nRendezvousLaunches(): Long = rendezvousLaunches.get()

    fun reset() {
        introduce2.set(0)
        rendezvousLaunches.set(0)
    }
}
