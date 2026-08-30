package org.kotlintor.hs

import java.util.concurrent.ConcurrentHashMap

/**
 * HS v3 descriptor / intro-state cache (C Tor `hs_cache.c`).
 *
 * Inventory: `L1:feature/hs/hs_cache.c`
 *
 * Dir-side stores encoded descriptor documents by blinded onion id query;
 * client-side stores decrypted outer+inner by service identity hex;
 * dirconn identity tags mirror `hs_ident_dir_conn_t` for in-flight fetches.
 */
class HsCache(
    var maxDescriptorBytes: Int = DEFAULT_MAX_DESC,
    var maxEntries: Int = DEFAULT_MAX_ENTRIES,
    var maxLifetimeSec: Long = DEFAULT_LIFETIME_SEC,
) {
    data class DirEntry(
        val query: String,
        val document: String,
        val storedAtMs: Long = System.currentTimeMillis(),
        var downloaded: Boolean = false,
    )

    data class ClientEntry(
        val serviceIdHex: String,
        val outer: HsDescriptorOuter,
        val inner: HsDescriptorInner,
        val encoded: String?,
        val storedAtMs: Long = System.currentTimeMillis(),
    )

    data class IntroState(
        val introIdHex: String,
        var timedOut: Boolean = false,
        var unreachableCount: Int = 0,
        var lastNoteMs: Long = System.currentTimeMillis(),
    )

    private val asDir = ConcurrentHashMap<String, DirEntry>()
    private val asClient = ConcurrentHashMap<String, ClientEntry>()
    private val introByService = ConcurrentHashMap<String, ConcurrentHashMap<String, IntroState>>()
    private val dirConnByKey = ConcurrentHashMap<String, HsIdentDirConn>()
    private var allocatedBytes: Long = 0

    fun storeAsDir(query: String, document: String): Boolean {
        val q = query.uppercase()
        if (document.length > maxDescriptorBytes) return false
        val prev = asDir[q]
        if (prev != null) allocatedBytes -= prev.document.length.toLong()
        asDir[q] = DirEntry(q, document)
        allocatedBytes += document.length.toLong()
        trimDir()
        return true
    }

    fun lookupAsDir(query: String): String? = asDir[query.uppercase()]?.document

    fun markDownloadedAsDir(query: String) {
        asDir[query.uppercase()]?.downloaded = true
    }

    fun storeAsClient(
        serviceIdHex: String,
        outer: HsDescriptorOuter,
        inner: HsDescriptorInner,
        encoded: String? = null,
    ) {
        val key = serviceIdHex.uppercase()
        val prev = asClient.remove(key)
        if (prev != null) allocatedBytes -= (prev.encoded?.length ?: 0).toLong()
        asClient[key] = ClientEntry(key, outer, inner, encoded)
        if (encoded != null) allocatedBytes += encoded.length.toLong()
        trimClient()
    }

    fun lookupAsClient(serviceIdHex: String): ClientEntry? = asClient[serviceIdHex.uppercase()]

    fun removeAsClient(serviceIdHex: String) {
        val prev = asClient.remove(serviceIdHex.uppercase()) ?: return
        allocatedBytes -= (prev.encoded?.length ?: 0).toLong()
    }

    fun purgeAsClient() {
        asClient.values.forEach { allocatedBytes -= (it.encoded?.length ?: 0).toLong() }
        asClient.clear()
        introByService.clear()
    }

    fun cleanAsDir(nowMs: Long = System.currentTimeMillis()) {
        val ttl = maxLifetimeSec * 1000
        asDir.entries.removeIf { (_, e) ->
            val old = nowMs - e.storedAtMs > ttl
            if (old) allocatedBytes -= e.document.length.toLong()
            old
        }
    }

    fun cleanAsClient(nowMs: Long = System.currentTimeMillis()) {
        val ttl = maxLifetimeSec * 1000
        asClient.entries.removeIf { (_, e) ->
            val old = nowMs - e.storedAtMs > ttl
            if (old) allocatedBytes -= (e.encoded?.length ?: 0).toLong()
            old
        }
        introByService.values.forEach { m ->
            m.entries.removeIf { (_, s) -> nowMs - s.lastNoteMs > ttl }
        }
    }

    fun noteIntroState(serviceIdHex: String, introIdHex: String, timedOut: Boolean = false) {
        val svc = introByService.getOrPut(serviceIdHex.uppercase()) { ConcurrentHashMap() }
        val st = svc.getOrPut(introIdHex.uppercase()) { IntroState(introIdHex.uppercase()) }
        st.lastNoteMs = System.currentTimeMillis()
        if (timedOut) {
            st.timedOut = true
            st.unreachableCount++
        }
    }

    fun findIntroState(serviceIdHex: String, introIdHex: String): IntroState? =
        introByService[serviceIdHex.uppercase()]?.get(introIdHex.uppercase())

    /** Attach dirconn identity for an in-flight HSDir fetch (C Tor hs_cache + hs_ident). */
    fun noteDirConn(ident: HsIdentDirConn) {
        dirConnByKey[ident.serviceIdentityHex.uppercase()] = ident
    }

    fun findDirConn(serviceIdHex: String): HsIdentDirConn? =
        dirConnByKey[serviceIdHex.uppercase()]

    fun clearDirConn(serviceIdHex: String) {
        dirConnByKey.remove(serviceIdHex.uppercase())
    }

    fun totalAllocation(): Long = allocatedBytes.coerceAtLeast(0)

    fun dirSize(): Int = asDir.size

    fun clientSize(): Int = asClient.size

    fun handleOom(minRemoveBytes: Int): Int {
        var removed = 0
        val dirOldest = asDir.values.sortedBy { it.storedAtMs }
        for (e in dirOldest) {
            if (removed >= minRemoveBytes) break
            asDir.remove(e.query)
            allocatedBytes -= e.document.length.toLong()
            removed += e.document.length
        }
        return removed
    }

    private fun trimDir() {
        while (asDir.size > maxEntries) {
            val oldest = asDir.values.minByOrNull { it.storedAtMs } ?: break
            asDir.remove(oldest.query)
            allocatedBytes -= oldest.document.length.toLong()
        }
    }

    private fun trimClient() {
        while (asClient.size > maxEntries) {
            val oldest = asClient.values.minByOrNull { it.storedAtMs } ?: break
            asClient.remove(oldest.serviceIdHex)
            allocatedBytes -= (oldest.encoded?.length ?: 0).toLong()
        }
    }

    companion object {
        const val DEFAULT_MAX_DESC: Int = 50_000
        const val DEFAULT_MAX_ENTRIES: Int = 256
        const val DEFAULT_LIFETIME_SEC: Long = 48L * 3600
    }

    /** C Tor `cache_clean_v3_as_dir`. */
    fun cacheCleanV3AsDir(nowMs: Long = System.currentTimeMillis()) {
        cleanAsDir(nowMs)
    }

    /**
     * C Tor `cache_clean_v3_by_downloaded_as_dir` — drop entries never marked downloaded.
     */
    fun cacheCleanV3ByDownloadedAsDir() {
        asDir.entries.removeIf { (_, e) ->
            if (!e.downloaded) {
                allocatedBytes -= e.document.length.toLong()
                true
            } else {
                false
            }
        }
    }

    /** C Tor `dir_set_downloaded`. */
    fun dirSetDownloaded(query: String) {
        markDownloadedAsDir(query)
    }

    /** C Tor `hs_cache_clean_as_dir`. */
    fun hsCacheCleanAsDir(nowMs: Long = System.currentTimeMillis()) = cleanAsDir(nowMs)

    /** C Tor `hs_cache_clean_as_client`. */
    fun hsCacheCleanAsClient(nowMs: Long = System.currentTimeMillis()) = cleanAsClient(nowMs)

    /** C Tor `hs_cache_client_intro_state_note`. */
    fun hsCacheClientIntroStateNote(serviceIdHex: String, introIdHex: String, timedOut: Boolean = false) =
        noteIntroState(serviceIdHex, introIdHex, timedOut)

    /** C Tor `hs_cache_client_intro_state_find`. */
    fun hsCacheClientIntroStateFind(serviceIdHex: String, introIdHex: String): IntroState? =
        findIntroState(serviceIdHex, introIdHex)

    /** C Tor `hs_cache_client_intro_state_clean`. */
    fun hsCacheClientIntroStateClean(nowMs: Long = System.currentTimeMillis()) {
        val ttl = maxLifetimeSec * 1000
        introByService.values.forEach { m ->
            m.entries.removeIf { (_, s) -> nowMs - s.lastNoteMs > ttl }
        }
    }

    /** C Tor `hs_cache_client_intro_state_purge`. */
    fun hsCacheClientIntroStatePurge() {
        introByService.clear()
    }

    /**
     * C Tor `hs_cache_client_new_auth_parse` — `onion-address:x25519-priv` line.
     * Returns onion address or null.
     */
    fun hsCacheClientNewAuthParse(line: String): String? {
        val p = line.trim().split(':', limit = 2)
        if (p.size != 2) return null
        val onion = p[0].trim().lowercase()
        if (!onion.endsWith(".onion")) return null
        return onion
    }

    /** C Tor `hs_cache_decrement_allocation`. */
    fun hsCacheDecrementAllocation(bytes: Int) {
        allocatedBytes = (allocatedBytes - bytes).coerceAtLeast(0)
    }

    /** C Tor `hs_cache_free_all`. */
    fun hsCacheFreeAll() {
        asDir.clear()
        asClient.clear()
        introByService.clear()
        dirConnByKey.clear()
        allocatedBytes = 0
    }

    /** C Tor `hs_cache_get_max_bytes`. */
    fun hsCacheGetMaxBytes(): Int = maxDescriptorBytes

    /** C Tor `hs_cache_get_max_descriptor_size` — same bound as max descriptor bytes. */
    fun hsCacheGetMaxDescriptorSize(): Int = maxDescriptorBytes

    /** C Tor `hs_cache_get_total_allocation`. */
    fun hsCacheGetTotalAllocation(): Long = totalAllocation()

    /** C Tor `hs_cache_handle_oom`. */
    fun hsCacheHandleOom(minRemoveBytes: Int): Int = handleOom(minRemoveBytes)

    /** C Tor `hs_cache_increment_allocation`. */
    fun hsCacheIncrementAllocation(bytes: Int) {
        allocatedBytes += bytes.coerceAtLeast(0).toLong()
    }

    /** C Tor `hs_cache_init` — reset to empty ready state. */
    fun hsCacheInit() {
        hsCacheFreeAll()
    }

    /** C Tor `hs_cache_lookup_as_client`. */
    fun hsCacheLookupAsClient(serviceIdHex: String): ClientEntry? = lookupAsClient(serviceIdHex)

    /** C Tor `hs_cache_lookup_as_dir`. */
    fun hsCacheLookupAsDir(query: String): String? = lookupAsDir(query)

    /** C Tor `hs_cache_lookup_encoded_as_client`. */
    fun hsCacheLookupEncodedAsClient(serviceIdHex: String): String? =
        lookupAsClient(serviceIdHex)?.encoded

    /** C Tor `hs_cache_mark_dowloaded_as_dir` (C Tor spelling). */
    fun hsCacheMarkDowloadedAsDir(query: String) = markDownloadedAsDir(query)

    /** C Tor `hs_cache_purge_as_client`. */
    fun hsCachePurgeAsClient() = purgeAsClient()

    /** C Tor `hs_cache_remove_as_client`. */
    fun hsCacheRemoveAsClient(serviceIdHex: String) = removeAsClient(serviceIdHex)

    /** C Tor `hs_cache_store_as_client`. */
    fun hsCacheStoreAsClient(
        serviceIdHex: String,
        outer: HsDescriptorOuter,
        inner: HsDescriptorInner,
        encoded: String? = null,
    ) = storeAsClient(serviceIdHex, outer, inner, encoded)

    /** C Tor `hs_cache_store_as_dir` convenience. */
    fun hsCacheStoreAsDir(query: String, document: String): Boolean = storeAsDir(query, document)
}
