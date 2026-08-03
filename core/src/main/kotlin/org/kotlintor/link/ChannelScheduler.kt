package org.kotlintor.link

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Channel write scheduler types from C Tor `scheduler.h`.
 *
 * Full KIST socket-accounting is not ported; this provides the type switch and
 * a byte-budget flush gate so OR connections can pace writes like KIST-Lite.
 */
enum class SchedulerType {
    NONE,
    VANILLA,
    KIST,
    KIST_LITE,
}

object ChannelScheduler {
    fun parseList(csv: String): List<SchedulerType> =
        csv.split(',').mapNotNull { tok ->
            when (tok.trim().lowercase()) {
                "vanilla" -> SchedulerType.VANILLA
                "kist" -> SchedulerType.KIST
                "kistlite", "kist-lite", "kist_lite" -> SchedulerType.KIST_LITE
                "none" -> SchedulerType.NONE
                "" -> null
                else -> null
            }
        }

    /** Prefer first supported type (KIST → KIST_LITE → VANILLA). */
    fun select(preferred: List<SchedulerType>): SchedulerType {
        for (t in preferred) {
            when (t) {
                SchedulerType.KIST, SchedulerType.KIST_LITE, SchedulerType.VANILLA -> return t
                SchedulerType.NONE -> continue
            }
        }
        return SchedulerType.VANILLA
    }
}

/**
 * Global pending-channel run queue (C Tor `scheduler_channel_*` / pending list lite).
 *
 * Channels with outbuf cells move to PENDING; [drain] invokes registered flush
 * callbacks until idle or [maxChannels] processed.
 */
object ChannelSchedulerPending {
    fun interface FlushHook {
        suspend fun flush(): Int
    }

    private val pending = CopyOnWriteArrayList<Long>()
    private val hooks = ConcurrentHashMap<Long, FlushHook>()
    private val channels = ConcurrentHashMap<Long, OrChannel>()
    /** Per-channel flush counts for multi-OR fairness diagnostics. */
    private val flushCounts = ConcurrentHashMap<Long, Long>()

    fun register(ch: OrChannel, hook: FlushHook) {
        channels[ch.globalId] = ch
        hooks[ch.globalId] = hook
        flushCounts.putIfAbsent(ch.globalId, 0L)
    }

    fun unregister(channelId: Long) {
        pending.remove(channelId)
        hooks.remove(channelId)
        channels.remove(channelId)
        flushCounts.remove(channelId)
    }

    fun notePending(channelId: Long) {
        val ch = channels[channelId] ?: return
        if (ch.schedState == ChannelSchedState.PENDING || ch.cellsQueued > 0 || ch.outbufBytes > 0) {
            if (!pending.contains(channelId)) pending.add(channelId)
        }
    }

    fun notePending(ch: OrChannel) = notePending(ch.globalId)

    fun pendingCount(): Int = pending.size

    fun registeredCount(): Int = channels.size

    fun flushCount(channelId: Long): Long = flushCounts[channelId] ?: 0L

    /** Max−min flush counts across registered channels (0 if ≤1 channel). */
    fun fairnessSpread(): Long {
        if (flushCounts.size <= 1) return 0
        val vals = flushCounts.values
        return (vals.maxOrNull() ?: 0) - (vals.minOrNull() ?: 0)
    }

    fun clear() {
        pending.clear()
        hooks.clear()
        channels.clear()
        flushCounts.clear()
    }

    /**
     * Drain up to [maxChannels] pending channels (FIFO); returns total items flushed.
     */
    suspend fun drain(maxChannels: Int = 32): Int {
        var flushed = 0
        var n = 0
        while (n < maxChannels && pending.isNotEmpty()) {
            val id = pending.removeAt(0)
            n++
            val hook = hooks[id] ?: continue
            val wrote = runCatching { hook.flush() }.getOrDefault(0)
            flushed += wrote
            if (wrote > 0) {
                flushCounts.merge(id, 1L) { a, b -> a + b }
            }
            val ch = channels[id]
            if (ch != null && (ch.cellsQueued > 0 || ch.outbufBytes > 0)) {
                pending.add(id) // round-robin: requeue at tail
            }
        }
        return flushed
    }

    /**
     * Fair drain: one flush attempt per registered channel that has work,
     * ordered by ascending historical flush count (starve-avoidance).
     */
    suspend fun drainFair(maxChannels: Int = 32): Int {
        val ordered = channels.keys
            .sortedBy { flushCounts[it] ?: 0L }
            .take(maxChannels)
        var flushed = 0
        for (id in ordered) {
            val ch = channels[id] ?: continue
            if (ch.cellsQueued <= 0 && ch.outbufBytes <= 0 && !pending.contains(id)) continue
            pending.remove(id)
            val hook = hooks[id] ?: continue
            val wrote = runCatching { hook.flush() }.getOrDefault(0)
            flushed += wrote
            if (wrote > 0) {
                flushCounts.merge(id, 1L) { a, b -> a + b }
            }
            if (ch.cellsQueued > 0 || ch.outbufBytes > 0) {
                if (!pending.contains(id)) pending.add(id)
            }
        }
        return flushed
    }
}

/**
 * Per-channel flush budget. Vanilla has no limit; KIST refills from
 * [KistMath] / [org.kotlintor.os.LinuxTcpInfo] when wired by [OrConnection.send].
 */
class WriteBudget(
    var type: SchedulerType = SchedulerType.VANILLA,
    /** Bytes allowed per [refill] for KIST / KIST_LITE. */
    var tickBudgetBytes: Int = 16 * 1024,
    var sockBufSizeFactor: Double = 1.0,
) {
    private var remaining: Int = tickBudgetBytes

    fun refill(kistInfo: KistMath.SocketInfo? = null) {
        remaining = when (type) {
            SchedulerType.VANILLA, SchedulerType.NONE -> Int.MAX_VALUE
            SchedulerType.KIST -> {
                val lim = if (kistInfo != null) {
                    KistMath.computeLimit(kistInfo, sockBufSizeFactor)
                } else {
                    KistMath.liteLimit()
                }
                lim.coerceAtMost(Int.MAX_VALUE.toLong()).toInt().coerceAtLeast(0)
            }
            SchedulerType.KIST_LITE -> tickBudgetBytes
        }
    }

    /** Returns how many of [want] bytes may be written now. */
    fun allow(want: Int): Int {
        if (want <= 0) return 0
        return when (type) {
            SchedulerType.VANILLA, SchedulerType.NONE -> want
            SchedulerType.KIST, SchedulerType.KIST_LITE -> {
                val n = minOf(want, remaining.coerceAtLeast(0))
                remaining -= n
                n
            }
        }
    }

    /** True if a full atomic write of [want] bytes is permitted (consumes budget). */
    fun tryAllowFull(want: Int): Boolean {
        if (want <= 0) return true
        return when (type) {
            SchedulerType.VANILLA, SchedulerType.NONE -> true
            SchedulerType.KIST, SchedulerType.KIST_LITE -> {
                if (remaining < want) return false
                remaining -= want
                true
            }
        }
    }

    val available: Int
        get() = when (type) {
            SchedulerType.VANILLA, SchedulerType.NONE -> Int.MAX_VALUE
            else -> remaining.coerceAtLeast(0)
        }
}
