package org.kotlintor.or

import java.util.concurrent.ConcurrentHashMap

/** C Tor `desc_store_t`. */
class DescStore {
    private val byDigest = ConcurrentHashMap<String, String>()
    fun store(digestHex: String, body: String) {
        byDigest[digestHex.uppercase()] = body
    }
    fun lookup(digestHex: String): String? = byDigest[digestHex.uppercase()]
    fun size(): Int = byDigest.size
}
