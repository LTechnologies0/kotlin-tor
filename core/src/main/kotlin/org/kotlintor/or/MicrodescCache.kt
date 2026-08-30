package org.kotlintor.or

import java.util.concurrent.ConcurrentHashMap

/** C Tor `microdesc_cache_t`. */
class MicrodescCache {
    private val byDigest = ConcurrentHashMap<String, String>()
    fun put(digestHex: String, body: String) {
        byDigest[digestHex.lowercase()] = body
    }
    fun get(digestHex: String): String? = byDigest[digestHex.lowercase()]
    fun size(): Int = byDigest.size
}
