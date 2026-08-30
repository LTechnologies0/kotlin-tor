package org.kotlintor.dir

import java.util.concurrent.ConcurrentHashMap

/**
 * Unparseable document dump store (C Tor `unparseable.c`).
 *
 * Inventory: `L1:feature/dirparse/unparseable.c`
 */
object UnparseableDump {
    private val dumps = ConcurrentHashMap<String, String>()

    fun note(tag: String, body: String) {
        dumps[tag] = body.take(64_000)
    }

    fun get(tag: String): String? = dumps[tag]

    fun clear() = dumps.clear()

    fun size(): Int = dumps.size

    fun tags(): Set<String> = dumps.keys.toSet()
}

object Unparseable {
    fun note(tag: String, body: String) = UnparseableDump.note(tag, body)
    fun get(tag: String) = UnparseableDump.get(tag)
    fun clear() = UnparseableDump.clear()
    fun size() = UnparseableDump.size()
}
