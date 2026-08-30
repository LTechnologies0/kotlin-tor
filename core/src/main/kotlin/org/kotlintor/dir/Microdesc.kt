package org.kotlintor.dir

import java.util.concurrent.ConcurrentHashMap

/**
 * Microdescriptor store helpers (C Tor `microdesc.c`).
 *
 * Inventory: `L1:feature/nodelist/microdesc.c`
 */
object Microdesc {
    data class Entry(
        val digest256Hex: String,
        val body: String,
        val lastListedMs: Long = System.currentTimeMillis(),
    )

    private val cache = ConcurrentHashMap<String, Entry>()
    private val outdatedDirservers = ConcurrentHashMap.newKeySet<String>()
    @Volatile private var generation: Long = 0

    fun parseFamily(document: String): Set<String> = MicrodescParse.parseFamily(document)

    /** C Tor `get_microdesc_cache`. */
    fun getMicrodescCache(): Map<String, Entry> = LinkedHashMap(cache)

    /** C Tor `microdesc_cache_clean` — drop entries older than [maxAgeMs]. */
    fun microdescCacheClean(maxAgeMs: Long = 7L * 24 * 3600_000): Int {
        val now = System.currentTimeMillis()
        val before = cache.size
        cache.entries.removeIf { now - it.value.lastListedMs > maxAgeMs }
        return before - cache.size
    }

    /** C Tor `microdesc_cache_clear`. */
    fun microdescCacheClear() = cache.clear()

    /** C Tor `microdesc_cache_lookup_by_digest256`. */
    fun microdescCacheLookupByDigest256(digest256Hex: String): Entry? =
        cache[digest256Hex.lowercase()]

    /** C Tor `microdesc_cache_rebuild`. */
    fun microdescCacheRebuild(): Int {
        generation++
        return cache.size
    }

    /** C Tor `microdesc_cache_reload` — no disk; returns current size. */
    fun microdescCacheReload(): Int = cache.size

    /** C Tor `microdesc_check_counts`. */
    fun microdescCheckCounts(): Pair<Int, Long> = cache.size to generation

    /** C Tor `microdesc_free_`. */
    fun microdescFree_(entry: Entry?): Entry? {
        entry?.let { cache.remove(it.digest256Hex.lowercase()) }
        return null
    }

    /** C Tor `microdesc_free_all`. */
    fun microdescFreeAll() {
        cache.clear()
        outdatedDirservers.clear()
        generation = 0
    }

    /** C Tor `microdesc_list_missing_digest256`. */
    fun microdescListMissingDigest256(wanted: List<String>): List<String> =
        wanted.filter { cache[it.lowercase()] == null }

    /** C Tor `microdesc_note_outdated_dirserver`. */
    fun microdescNoteOutdatedDirserver(identityHex: String) {
        outdatedDirservers += identityHex.lowercase()
    }

    /** C Tor `microdesc_relay_is_outdated_dirserver`. */
    fun microdescRelayIsOutdatedDirserver(identityHex: String): Boolean =
        identityHex.lowercase() in outdatedDirservers

    /** C Tor `microdesc_reset_outdated_dirservers_list`. */
    fun microdescResetOutdatedDirserversList() = outdatedDirservers.clear()

    /** C Tor `microdescs_add_to_cache`. */
    fun microdescsAddToCache(digest256Hex: String, body: String): Entry {
        val e = Entry(digest256Hex.lowercase(), body)
        cache[e.digest256Hex] = e
        return e
    }

    /** C Tor `microdescs_add_list_to_cache`. */
    fun microdescsAddListToCache(items: List<Pair<String, String>>): Int {
        var n = 0
        for ((d, b) in items) {
            microdescsAddToCache(d, b)
            n++
        }
        return n
    }
}
