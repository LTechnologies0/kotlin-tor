package org.kotlintor.relay

/**
 * Bandwidth history (C Tor `bwhist.c`).
 *
 * Inventory: `L1:feature/stats/bwhist.c`
 */
object BwHist {
    private const val NUM_INTERVALS = 96 // C Tor default observation slots

    /** C Tor `bw_array_t` observation slot. */
    data class BwArray(
        var read: Long = 0,
        var written: Long = 0,
        var dirRead: Long = 0,
        var dirWritten: Long = 0,
    )

    data class Slot(
        var read: Long = 0,
        var written: Long = 0,
        var dirRead: Long = 0,
        var dirWritten: Long = 0,
    ) {
        fun toBwArray(): BwArray = BwArray(read, written, dirRead, dirWritten)
    }

    private val slots = Array(NUM_INTERVALS) { Slot() }
    private var cursor: Int = 0
    private var lastAdvanceEpochSec: Long = System.currentTimeMillis() / 1000
    private val intervalSec: Long = 900 // 15 min

    @Synchronized
    fun noteBytesRead(n: Long, whenEpochSec: Long = System.currentTimeMillis() / 1000, ipv6: Boolean = false) {
        advance(whenEpochSec)
        slots[cursor].read += n.coerceAtLeast(0)
    }

    @Synchronized
    fun noteBytesWritten(n: Long, whenEpochSec: Long = System.currentTimeMillis() / 1000, ipv6: Boolean = false) {
        advance(whenEpochSec)
        slots[cursor].written += n.coerceAtLeast(0)
    }

    @Synchronized
    fun noteDirBytesRead(n: Long, whenEpochSec: Long = System.currentTimeMillis() / 1000) {
        advance(whenEpochSec)
        slots[cursor].dirRead += n.coerceAtLeast(0)
    }

    @Synchronized
    fun noteDirBytesWritten(n: Long, whenEpochSec: Long = System.currentTimeMillis() / 1000) {
        advance(whenEpochSec)
        slots[cursor].dirWritten += n.coerceAtLeast(0)
    }

    /** Max observed combined throughput (bytes/interval) for bandwidth assess. */
    @Synchronized
    fun bandwidthAssess(): Long =
        slots.maxOf { it.read + it.written }

    @Synchronized
    fun getBandwidthLines(): String = buildString {
        appendLine("write-history ${formatHist { it.written }}")
        appendLine("read-history ${formatHist { it.read }}")
        appendLine("dirreq-write-history ${formatHist { it.dirWritten }}")
        appendLine("dirreq-read-history ${formatHist { it.dirRead }}")
    }

    @Synchronized
    fun clear() {
        for (i in slots.indices) slots[i] = Slot()
        cursor = 0
    }

    private fun advance(now: Long) {
        if (intervalSec <= 0) return
        val steps = ((now - lastAdvanceEpochSec) / intervalSec).toInt().coerceAtMost(NUM_INTERVALS)
        repeat(steps) {
            cursor = (cursor + 1) % NUM_INTERVALS
            slots[cursor] = Slot()
            lastAdvanceEpochSec += intervalSec
        }
        if (steps == 0 && now < lastAdvanceEpochSec) {
            // clock skew — ignore
        }
    }

    private fun formatHist(sel: (Slot) -> Long): String {
        val vals = (0 until NUM_INTERVALS).map { i ->
            val idx = (cursor + 1 + i) % NUM_INTERVALS
            sel(slots[idx])
        }
        return vals.joinToString(",")
    }
}
