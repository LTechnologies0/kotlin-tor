package org.kotlintor.dir

/**
 * Bandwidth-authority file helpers (C Tor `bwauth.c`).
 *
 * Inventory: `L1:feature/dirauth/bwauth.c`
 *
 * Implementation: [BwAuthFile].
 */
object BwAuth {
    const val MAX_MEASUREMENT_AGE_SEC: Long = BwAuthFile.MAX_MEASUREMENT_AGE_SEC

    private val measuredCache = MeasuredBwCache()
    @Volatile private var lastNMeasured: Int = 0

    fun parse(text: String): BwAuthFile.Parsed = BwAuthFile.parse(text)

    fun parseRelayLine(line: String): BwAuthFile.MeasuredLine? = BwAuthFile.parseRelayLine(line)

    /** C Tor `dirserv_cache_measured_bw`. */
    fun dirservCacheMeasuredBw(nodeIdHex: String, bwKb: Long, asOfEpochSec: Long = System.currentTimeMillis() / 1000) {
        measuredCache.put(nodeIdHex, bwKb, asOfEpochSec)
    }

    /** C Tor `dirserv_clear_measured_bw_cache`. */
    fun dirservClearMeasuredBwCache() {
        measuredCache.clear()
        lastNMeasured = 0
    }

    /** C Tor `dirserv_expire_measured_bw_cache`. */
    fun dirservExpireMeasuredBwCache(nowEpochSec: Long = System.currentTimeMillis() / 1000) {
        measuredCache.expire(nowEpochSec)
    }

    /** C Tor `dirserv_count_measured_bws` — count cache entries still valid. */
    fun dirservCountMeasuredBws(nowEpochSec: Long = System.currentTimeMillis() / 1000): Int {
        measuredCache.expire(nowEpochSec)
        return measuredCache.size
    }

    fun measuredBw(nodeIdHex: String, nowEpochSec: Long = System.currentTimeMillis() / 1000): Long? =
        measuredCache.get(nodeIdHex, nowEpochSec)

    /** C Tor `dirserv_has_measured_bw`. */
    fun dirservHasMeasuredBw(nodeIdHex: String, nowEpochSec: Long = System.currentTimeMillis() / 1000): Boolean =
        measuredBw(nodeIdHex, nowEpochSec) != null

    /** C Tor `dirserv_get_measured_bw_cache_size`. */
    fun dirservGetMeasuredBwCacheSize(): Int = measuredCache.size

    /** C Tor `dirserv_query_measured_bw_cache_kb` — returns kb or null. */
    fun dirservQueryMeasuredBwCacheKb(
        nodeIdHex: String,
        nowEpochSec: Long = System.currentTimeMillis() / 1000,
    ): Long? = measuredBw(nodeIdHex, nowEpochSec)

    /** C Tor `dirserv_get_last_n_measured_bws`. */
    fun dirservGetLastNMeasuredBws(): Int = lastNMeasured

    /**
     * C Tor `dirserv_get_credible_bandwidth_kb` — prefer measured, else advertised.
     */
    fun dirservGetCredibleBandwidthKb(
        identityHex: String,
        advertisedKb: Long,
        nowEpochSec: Long = System.currentTimeMillis() / 1000,
    ): Long = measuredBw(identityHex, nowEpochSec) ?: advertisedKb

    /**
     * C Tor `dirserv_read_measured_bandwidths` — parse file text into cache.
     * Returns number of lines loaded.
     */
    fun dirservReadMeasuredBandwidths(
        text: String,
        asOfEpochSec: Long = System.currentTimeMillis() / 1000,
    ): Int {
        val parsed = parse(text)
        measuredCache.load(parsed, asOfEpochSec)
        lastNMeasured = parsed.lines.size
        return parsed.lines.size
    }

    /** C Tor `measured_bw_line_parse`. */
    fun measuredBwLineParse(line: String): BwAuthFile.MeasuredLine? = parseRelayLine(line)

    /** C Tor `measured_bw_line_apply`. */
    fun measuredBwLineApply(
        line: BwAuthFile.MeasuredLine,
        asOfEpochSec: Long = System.currentTimeMillis() / 1000,
    ) {
        dirservCacheMeasuredBw(line.nodeIdHex, line.bwKb, asOfEpochSec)
    }
}
