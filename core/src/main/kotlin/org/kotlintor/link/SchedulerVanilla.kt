package org.kotlintor.link

/**
 * Vanilla (non-KIST) channel scheduler (C Tor `scheduler_vanilla.c`).
 *
 * Inventory: `L1:core/or/scheduler_vanilla.c`
 *
 * Round-robin / EWMA-agnostic flush ordering over ready channels.
 */
object SchedulerVanilla {
    data class ChannelRef(val id: Long, var cellsQueued: Int = 0, var pending: Boolean = false)

    private val ready = ArrayDeque<ChannelRef>()

    fun reset() {
        ready.clear()
    }

    fun notePending(ch: ChannelRef) {
        ch.pending = true
        if (ready.none { it.id == ch.id }) ready.addLast(ch)
    }

    fun noteIdle(ch: ChannelRef) {
        ch.pending = false
        ready.removeAll { it.id == ch.id }
    }

    /** Pick next channel with queued cells (FIFO among pending). */
    fun next(): ChannelRef? {
        while (ready.isNotEmpty()) {
            val ch = ready.removeFirst()
            if (ch.pending && ch.cellsQueued > 0) {
                ready.addLast(ch)
                return ch
            }
        }
        return null
    }

    fun pendingCount(): Int = ready.count { it.pending && it.cellsQueued > 0 }
}
