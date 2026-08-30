package org.kotlintor.status

import org.kotlintor.relay.BwHist
import org.kotlintor.stats.ConnStats
import org.kotlintor.stats.HsStats
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicInteger

/**
 * Heartbeat / status line formatter (C Tor `status.c` / `status.h`).
 *
 * Inventory: `L1:core/or/status.c`
 */
object HeartbeatStatus {
    private val startedAtMs = AtomicLong(System.currentTimeMillis())
    private val heartbeatsEmitted = AtomicLong(0)
    private val lastHeartbeatMs = AtomicLong(0)

    private val nIncomingIpv4 = AtomicInteger(0)
    private val nIncomingIpv6 = AtomicInteger(0)
    private val nOutgoingIpv4 = AtomicInteger(0)
    private val nOutgoingIpv6 = AtomicInteger(0)

    private val nCircsClosedUnrecognized = AtomicInteger(0)
    private val nUnrecognizedCells = AtomicLong(0)
    private val nSecsUnrecognizedCircs = AtomicLong(0)

    fun resetClock(nowMs: Long = System.currentTimeMillis()) {
        startedAtMs.set(nowMs)
        heartbeatsEmitted.set(0)
        lastHeartbeatMs.set(0)
        nIncomingIpv4.set(0)
        nIncomingIpv6.set(0)
        nOutgoingIpv4.set(0)
        nOutgoingIpv6.set(0)
        nCircsClosedUnrecognized.set(0)
        nUnrecognizedCells.set(0)
        nSecsUnrecognizedCircs.set(0)
    }

    /** C Tor `secs_to_uptime`. */
    fun secsToUptime(secs: Long): String {
        val s = secs.coerceAtLeast(0)
        val days = s / 86400
        val hours = ((s - days * 86400) / 3600).toInt()
        val minutes = ((s - days * 86400 - hours * 3600) / 60).toInt()
        return when (days) {
            0L -> "%d:%02d hours".format(hours, minutes)
            1L -> "1 day %d:%02d hours".format(hours, minutes)
            else -> "%d days %d:%02d hours".format(days, hours, minutes)
        }
    }

    /** C Tor `bytes_to_usage`. */
    fun bytesToUsage(bytes: Long): String {
        val b = bytes.coerceAtLeast(0)
        return when {
            b < (1L shl 20) -> "${b shr 10} kB"
            b < (1L shl 30) -> "%.2f MB".format(b.toDouble() / (1 shl 20))
            else -> "%.2f GB".format(b.toDouble() / (1 shl 30))
        }
    }

    /**
     * C Tor `note_connection` — [ipv6]=false → AF_INET, true → AF_INET6.
     */
    fun noteConnection(inbound: Boolean, ipv6: Boolean) {
        when {
            inbound && !ipv6 -> nIncomingIpv4.incrementAndGet()
            inbound && ipv6 -> nIncomingIpv6.incrementAndGet()
            !inbound && !ipv6 -> nOutgoingIpv4.incrementAndGet()
            else -> nOutgoingIpv6.incrementAndGet()
        }
    }

    /** C Tor `note_circ_closed_for_unrecognized_cells`. */
    fun noteCircClosedForUnrecognizedCells(nSeconds: Long, nCells: Long) {
        nCircsClosedUnrecognized.incrementAndGet()
        nUnrecognizedCells.addAndGet(nCells.coerceAtLeast(0))
        if (nSeconds >= 0) nSecsUnrecognizedCircs.addAndGet(nSeconds)
    }

    fun countCircuits(openCircuits: Int): Int = openCircuits.coerceAtLeast(0)

    fun uptimeSec(nowMs: Long = System.currentTimeMillis()): Long =
        ((nowMs - startedAtMs.get()) / 1000L).coerceAtLeast(0)

    /**
     * C Tor `log_heartbeat` body as a single NOTICE-shaped string
     * (without writing to a logger).
     */
    fun logHeartbeat(
        bytesRead: Long,
        bytesWritten: Long,
        circuitsOpen: Int,
        hibernating: Boolean = false,
        inConsensus: Boolean? = null,
        nowMs: Long = System.currentTimeMillis(),
    ): String {
        heartbeatsEmitted.incrementAndGet()
        lastHeartbeatMs.set(nowMs)
        val uptime = secsToUptime(uptimeSec(nowMs))
        val sent = bytesToUsage(bytesWritten)
        val rcvd = bytesToUsage(bytesRead)
        return buildString {
            if (inConsensus == false) {
                append("Heartbeat: It seems like we are not in the cached consensus. ")
            }
            append("Heartbeat: Tor's uptime is $uptime, with $circuitsOpen circuits open. ")
            append("I've sent $sent and received $rcvd. ")
            append(
                "I've received ${nIncomingIpv4.get()} connections on IPv4 and " +
                    "${nIncomingIpv6.get()} on IPv6. I've made ${nOutgoingIpv4.get()} " +
                    "connections with IPv4 and ${nOutgoingIpv6.get()} with IPv6.",
            )
            if (hibernating) append(" We are currently hibernating.")
            if (nCircsClosedUnrecognized.get() > 0) {
                append(
                    " Closed ${nCircsClosedUnrecognized.get()} circuits for unrecognized cells " +
                        "(${nUnrecognizedCells.get()} cells).",
                )
            }
        }
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
        val uptimeSec = uptimeSec(nowMs)
        return buildString {
            append("Heartbeat: uptime=${secsToUptime(uptimeSec)}")
            append(" read=${bytesToUsage(bytesRead)} written=${bytesToUsage(bytesWritten)}")
            append(" bootstrapped=$bootstrapped")
            append(" circuits=$circuitsOpen orconns=$orConns")
            append(" in4=${nIncomingIpv4.get()} in6=${nIncomingIpv6.get()}")
            append(" out4=${nOutgoingIpv4.get()} out6=${nOutgoingIpv6.get()}")
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

    fun connectionCounts(): IntArray = intArrayOf(
        nIncomingIpv4.get(), nIncomingIpv6.get(),
        nOutgoingIpv4.get(), nOutgoingIpv6.get(),
    )
}
