package org.kotlintor.status

import org.kotlintor.relay.BwHist
import org.kotlintor.stats.ConnStats
import org.kotlintor.stats.HsStats
import java.util.concurrent.atomic.AtomicLong

/**
 * Heartbeat / status line formatter (C Tor `status.c` lite).
 *
 * Inventory: `L1:core/or/status.c`
 */
object HeartbeatStatus {
    private val startedAtMs = AtomicLong(System.currentTimeMillis())
    private val heartbeatsEmitted = AtomicLong(0)
    private val lastHeartbeatMs = AtomicLong(0)

    fun resetClock(nowMs: Long = System.currentTimeMillis()) {
        startedAtMs.set(nowMs)
        heartbeatsEmitted.set(0)
        lastHeartbeatMs.set(0)
    }

    fun format(
        bytesRead: Long,
        bytesWritten: Long,
        bootstrapped: Boolean,
        circuitsOpen: Int = 0,
        orConns: Int = 0,
        nowMs: Long = System.currentTimeMillis(),
    ): String {
        heartbeatsEmitted.incrementAndGet()
        lastHeartbeatMs.set(nowMs)
        val uptimeSec = ((nowMs - startedAtMs.get()) / 1000L).coerceAtLeast(0)
        return buildString {
            append("Heartbeat: uptime=${uptimeSec}s")
            append(" read=$bytesRead written=$bytesWritten")
            append(" bootstrapped=$bootstrapped")
            append(" circuits=$circuitsOpen orconns=$orConns")
            append(" hs_intro2=${HsStats.nIntroduce2V3Cells()}")
            append(" hs_rend=${HsStats.nRendezvousLaunches()}")
            append(" bw_assess=${BwHist.bandwidthAssess()}")
            append(" n=${heartbeatsEmitted.get()}")
        }
    }

    fun formatConnStats(): String = ConnStats.format()

    fun heartbeatCount(): Long = heartbeatsEmitted.get()

    fun lastHeartbeatAgeMs(nowMs: Long = System.currentTimeMillis()): Long {
        val last = lastHeartbeatMs.get()
        return if (last == 0L) -1 else (nowMs - last).coerceAtLeast(0)
    }
}
