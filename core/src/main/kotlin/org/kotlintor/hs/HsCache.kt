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
}
