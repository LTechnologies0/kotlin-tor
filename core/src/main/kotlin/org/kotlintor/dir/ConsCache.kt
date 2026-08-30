package org.kotlintor.dir

import org.kotlintor.crypto.Digests
import org.kotlintor.util.toHex

/**
 * Consensus / diff document cache (C Tor `conscache.c`).

 * Inventory: `L1:feature/dircache/conscache.c`
 */
class ConsCache(private val maxEntries: Int = 64) {
    data class Entry(
        val digestHex: String,
        val body: String,
        val storedAtEpochSec: Long,
    )

    private val byDigest = LinkedHashMap<String, Entry>(16, 0.75f, true)

    fun put(body: String, nowEpochSec: Long = System.currentTimeMillis() / 1000): Entry {
        val dig = Digests.sha3_256(body.toByteArray(Charsets.US_ASCII)).toHex().lowercase()
        val e = Entry(dig, body, nowEpochSec)
        synchronized(byDigest) {
            byDigest[dig] = e
            while (byDigest.size > maxEntries) {
                val eldest = byDigest.entries.iterator()
                if (eldest.hasNext()) {
                    eldest.next()
                    eldest.remove()
                } else break
            }
        }
        return e
    }

    fun get(digestHex: String): Entry? = synchronized(byDigest) {
        byDigest[digestHex.lowercase()]
    }

    fun getBySha3Prefix(prefixHex: String): Entry? = synchronized(byDigest) {
        val p = prefixHex.lowercase()
        byDigest.values.firstOrNull { it.digestHex.startsWith(p) }
    }

    fun size(): Int = synchronized(byDigest) { byDigest.size }

    fun clear() = synchronized(byDigest) { byDigest.clear() }
}
