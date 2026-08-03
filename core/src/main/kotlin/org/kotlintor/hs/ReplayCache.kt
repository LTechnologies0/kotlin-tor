package org.kotlintor.hs

import org.kotlintor.crypto.Digests
import java.util.concurrent.ConcurrentHashMap

/**
 * Self-scrubbing replay cache (C Tor `replaycache_t` / `hs_common/replaycache.c`).
 *
 * Keys are SHA-256 digests of observed blobs (e.g. INTRODUCE2 ENCRYPTED section).
 * Returns true if the digest was already seen within [horizonSec].
 */
class ReplayCache(
    /** Age-out window; 0 = never age out (only scrub removes). */
    private val horizonSec: Long = REND_REPLAY_TIME_INTERVAL_SEC,
    /** Scrub period; 0 = scrub on every add. */
    private val scrubIntervalSec: Long = REND_REPLAY_TIME_INTERVAL_SEC,
) {
    private val seen = ConcurrentHashMap<String, Long>()
    @Volatile private var lastScrubSec: Long = 0

    /**
     * @return true if this is a **replay** (already seen within horizon).
     */
    fun addAndTest(data: ByteArray, nowEpochSec: Long = System.currentTimeMillis() / 1000): Boolean {
        scrubIfNeeded(nowEpochSec)
        val key = Digests.sha256(data).joinToString("") { "%02x".format(it) }
        val prev = seen.putIfAbsent(key, nowEpochSec)
        if (prev == null) return false
        if (horizonSec > 0 && nowEpochSec - prev > horizonSec) {
            seen[key] = nowEpochSec
            return false
        }
        return true
    }

    fun scrubIfNeeded(nowEpochSec: Long = System.currentTimeMillis() / 1000) {
        if (scrubIntervalSec > 0 && nowEpochSec - lastScrubSec < scrubIntervalSec) return
        lastScrubSec = nowEpochSec
        if (horizonSec <= 0) return
        val cutoff = nowEpochSec - horizonSec
        seen.entries.removeIf { it.value < cutoff }
    }

    val size: Int get() = seen.size

    companion object {
        /** C Tor `REND_REPLAY_TIME_INTERVAL` (5 minutes). */
        const val REND_REPLAY_TIME_INTERVAL_SEC: Long = 5 * 60
    }
}
