package org.kotlintor.link

/**
 * KIST write-limit math from C Tor `scheduler_kist.c` `update_socket_info_impl`.
 *
 * Full `TCP_INFO` / `SIOCOUTQNSD` needs Linux kernel support via [org.kotlintor.os.PlatformNatives];
 * when unavailable, [liteLimit] matches KIST-Lite / Vanilla fallback.
 */
object KistMath {
    data class SocketInfo(
        val cwnd: Long = 0,
        val unacked: Long = 0,
        val mss: Long = 1460,
        val notSent: Long = 0,
        val outbufLen: Long = 0,
    )

    /**
     * @return byte write limit for this tick; 0 means do not write more.
     */
    fun computeLimit(info: SocketInfo, sockBufSizeFactor: Double = 1.0): Long {
        if (info.cwnd == 0L && info.mss == 0L) {
            // Fallback: unlimited (Vanilla behavior).
            return Long.MAX_VALUE
        }
        val tcpSpace = if (info.cwnd >= info.unacked) {
            (info.cwnd - info.unacked) * info.mss
        } else {
            0L
        }
        val extra = ((info.cwnd * info.mss).toDouble() * sockBufSizeFactor).toLong() -
            info.notSent - info.outbufLen
        val sum = tcpSpace + extra
        return if (sum < 0) 0 else sum
    }

    fun liteLimit(estimatedCells: Int = 32, cellBytes: Int = 514): Long =
        (estimatedCells.toLong() * cellBytes).coerceAtLeast(cellBytes.toLong())
}
