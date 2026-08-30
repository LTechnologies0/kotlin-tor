package org.kotlintor.relay

/**
 * DoS defenses (C Tor `dos.c`).
 *
 * Inventory: `L1:core/or/dos.c`
 *
 * Implementation: [DosGuard]. Subsystem lifecycle: [DosSys].
 */
object Dos {
    fun newGuard(
        maxConnsPerIp: Int = 32,
        maxCreatesPerMin: Int = 100,
        maxConcurrentCreates: Int = 8,
        maxStreamsPerMin: Int = Int.MAX_VALUE / 4,
        streamDefenseEnabled: Boolean = false,
    ): DosGuard =
        DosGuard(
            maxConnsPerIp = maxConnsPerIp,
            maxCreatesPerMin = maxCreatesPerMin,
            maxConcurrentCreates = maxConcurrentCreates,
            maxStreamsPerMin = maxStreamsPerMin,
            streamDefenseEnabled = streamDefenseEnabled,
        )

    fun fromOptions(o: DosOptions): DosGuard = DosGuard.fromOptions(o)

    fun allowConnection(guard: DosGuard, ip: String): Boolean = guard.allowConnection(ip)

    fun allowCreate(guard: DosGuard, ip: String): Boolean = guard.allowCreate(ip)

    fun allowStream(guard: DosGuard, ip: String): Boolean = guard.allowStream(ip)

    // --- C Tor dos.h op aliases (L3 head) ---

    @Volatile var enabled: Boolean = true
    private val markedCcAddrs = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

    data class CcBucket(
        var tokens: Double = 100.0,
        var lastRefillMs: Long = System.currentTimeMillis(),
        val ratePerSec: Double = 10.0,
        val burst: Double = 100.0,
    )

    /** C Tor `cc_stats_refill_bucket`. */
    fun ccStatsRefillBucket(bucket: CcBucket, nowMs: Long = System.currentTimeMillis()): CcBucket {
        val elapsed = ((nowMs - bucket.lastRefillMs).coerceAtLeast(0)) / 1000.0
        bucket.tokens = (bucket.tokens + elapsed * bucket.ratePerSec).coerceAtMost(bucket.burst)
        bucket.lastRefillMs = nowMs
        return bucket
    }

    /** C Tor `dos_cc_get_defense_type` — 0 none / 1 refuse / 2 resolve. */
    fun dosCcGetDefenseType(guard: DosGuard, ip: String): Int =
        if (!guard.allowCreate(ip)) 1 else 0

    /** C Tor `dos_cc_new_create_cell`. */
    fun dosCcNewCreateCell(guard: DosGuard, ip: String): Boolean = guard.allowCreate(ip)

    /** C Tor `dos_close_client_conn`. */
    fun dosCloseClientConn(guard: DosGuard, ip: String) = guard.releaseConnection(ip)

    /** C Tor `dos_conn_addr_get_defense_type`. */
    fun dosConnAddrGetDefenseType(guard: DosGuard, ip: String): Int =
        if (!guard.allowConnection(ip)) {
            guard.releaseConnection(ip)
            1
        } else {
            0
        }

    /** C Tor `dos_consensus_has_changed`. */
    fun dosConsensusHasChanged(params: Map<String, Long>) {
        enabled = (params["DoSCircuitCreationEnabled"] ?: 1L) != 0L
    }

    /** C Tor `dos_enabled`. */
    fun dosEnabled(): Boolean = enabled

    /** C Tor `dos_free_all`. */
    fun dosFreeAll() {
        markedCcAddrs.clear()
        enabled = true
        counters.ccRejected = 0
        counters.connAddrConnectRejected = 0
        counters.connAddrRejected = 0
        counters.singleHopRefused = 0
        counters.streamRejected = 0
        initialized = false
    }

    /** C Tor `dos_geoip_entry_about_to_free` / `dos_geoip_entry_init` stubs. */
    fun dosGeoipEntryAboutToFree(ip: String) {
        markedCcAddrs.remove(ip)
    }

    fun dosGeoipEntryInit(ip: String) {
        markedCcAddrs.add(ip)
    }

    /** C Tor `dos_get_num_cc_marked_addr`. */
    fun dosGetNumCcMarkedAddr(): Int = markedCcAddrs.size

    /** C Tor `dos_get_num_cc_marked_addr_maxq`. */
    fun dosGetNumCcMarkedAddrMaxq(): Int = markedCcAddrs.size

    // --- remaining dos.h L3 aliases ---

    private val counters = object {
        var ccRejected = 0L
        var connAddrConnectRejected = 0L
        var connAddrRejected = 0L
        var singleHopRefused = 0L
        var streamRejected = 0L
    }

    @Volatile private var refuseSingleHop: Boolean = false
    @Volatile private var initialized: Boolean = false

    data class StreamTbf(
        var tokens: Double = 100.0,
        var lastMs: Long = System.currentTimeMillis(),
        val rate: Double = 5.0,
        val burst: Double = 100.0,
    )

    /** C Tor `dos_get_num_cc_rejected`. */
    fun dosGetNumCcRejected(): Long = counters.ccRejected

    /** C Tor `dos_get_num_conn_addr_connect_rejected`. */
    fun dosGetNumConnAddrConnectRejected(): Long = counters.connAddrConnectRejected

    /** C Tor `dos_get_num_conn_addr_rejected`. */
    fun dosGetNumConnAddrRejected(): Long = counters.connAddrRejected

    /** C Tor `dos_get_num_single_hop_refused`. */
    fun dosGetNumSingleHopRefused(): Long = counters.singleHopRefused

    /** C Tor `dos_get_num_stream_rejected`. */
    fun dosGetNumStreamRejected(): Long = counters.streamRejected

    /** C Tor `dos_init`. */
    fun dosInit() {
        initialized = true
        enabled = true
    }

    /** C Tor `dos_log_heartbeat`. */
    fun dosLogHeartbeat(): String =
        "DoS: cc_rej=${counters.ccRejected} conn_rej=${counters.connAddrRejected} " +
            "stream_rej=${counters.streamRejected} single_hop=${counters.singleHopRefused}"

    /** C Tor `dos_new_client_conn`. */
    fun dosNewClientConn(guard: DosGuard, ip: String): Boolean {
        val ok = guard.allowConnection(ip)
        if (!ok) {
            counters.connAddrRejected++
            counters.connAddrConnectRejected++
        }
        return ok
    }

    /** C Tor `dos_note_circ_max_outq`. */
    fun dosNoteCircMaxOutq(addr: String) {
        markedCcAddrs.add(addr)
        counters.ccRejected++
    }

    /** C Tor `dos_note_refuse_single_hop_client`. */
    fun dosNoteRefuseSingleHopClient() {
        counters.singleHopRefused++
    }

    /** C Tor `dos_should_refuse_single_hop_client`. */
    fun dosShouldRefuseSingleHopClient(): Boolean = refuseSingleHop

    fun setRefuseSingleHopClient(v: Boolean) {
        refuseSingleHop = v
    }

    /** C Tor `dos_stream_init_circ_tbf`. */
    fun dosStreamInitCircTbf(): StreamTbf = StreamTbf()

    /** C Tor `dos_stream_new_begin_or_resolve_cell`. */
    fun dosStreamNewBeginOrResolveCell(guard: DosGuard, ip: String, tbf: StreamTbf): Boolean {
        ccStatsRefillBucket(
            CcBucket(tokens = tbf.tokens, lastRefillMs = tbf.lastMs, ratePerSec = tbf.rate, burst = tbf.burst),
        ).also {
            tbf.tokens = it.tokens
            tbf.lastMs = it.lastRefillMs
        }
        if (tbf.tokens < 1.0) {
            counters.streamRejected++
            return false
        }
        if (!guard.allowStream(ip)) {
            counters.streamRejected++
            return false
        }
        tbf.tokens -= 1.0
        return true
    }

    fun isInitialized(): Boolean = initialized
}
