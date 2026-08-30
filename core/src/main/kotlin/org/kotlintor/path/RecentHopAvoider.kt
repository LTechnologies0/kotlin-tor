package org.kotlintor.path

import java.util.ArrayDeque

/**
 * Ring buffer of recently used middle/exit fingerprints (client-local).
 * Does not track sticky entry guards.
 */
class RecentHopAvoider(
    private var capacity: Int = DEFAULT_CAPACITY,
    private val ttlMs: Long = DEFAULT_TTL_MS,
) {
    private data class Entry(val fingerprintHex: String, val atMs: Long)

    private val q = ArrayDeque<Entry>()
    private val set = linkedSetOf<String>()

    fun resize(newCapacity: Int) {
        capacity = newCapacity.coerceIn(1, 10_000)
        trim()
    }

    fun clear() {
        q.clear()
        set.clear()
    }

    fun contains(fingerprintHex: String, nowMs: Long = System.currentTimeMillis()): Boolean {
        expire(nowMs)
        return fingerprintHex.uppercase() in set
    }

    fun fingerprints(nowMs: Long = System.currentTimeMillis()): Set<String> {
        expire(nowMs)
        return set.toSet()
    }

    fun record(fingerprintHex: String, nowMs: Long = System.currentTimeMillis()) {
        expire(nowMs)
        val fp = fingerprintHex.uppercase()
        if (fp in set) {
            // Refresh: remove old position then re-add.
            q.removeIf { it.fingerprintHex == fp }
            set.remove(fp)
        }
        q.addLast(Entry(fp, nowMs))
        set.add(fp)
        trim()
    }

    fun recordMiddleAndExit(middleFp: String, exitFp: String, nowMs: Long = System.currentTimeMillis()) {
        record(middleFp, nowMs)
        record(exitFp, nowMs)
    }

    private fun expire(nowMs: Long) {
        while (q.isNotEmpty() && nowMs - q.first().atMs > ttlMs) {
            val e = q.removeFirst()
            set.remove(e.fingerprintHex)
        }
    }

    private fun trim() {
        while (q.size > capacity) {
            val e = q.removeFirst()
            set.remove(e.fingerprintHex)
        }
    }

    companion object {
        const val DEFAULT_CAPACITY: Int = 64
        const val DEFAULT_TTL_MS: Long = 60L * 60L * 1000L // 1 hour
    }
}
