package org.kotlintor.link

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.os.LinuxTcpInfo
import org.kotlintor.os.PlatformNatives

class KistAndPlatformTest {
    @Test
    fun `KIST missing TCP_INFO cwnd zero is unlimited`() {
        val lim = KistMath.computeLimit(
            KistMath.SocketInfo(cwnd = 0, unacked = 0, mss = 1460, notSent = 0, outbufLen = 514),
        )
        assertEquals(Long.MAX_VALUE, lim)
    }

    @Test
    fun `ChannelScheduler skips full KIST unless python probe opted in`() {
        val selected = ChannelScheduler.select(
            listOf(SchedulerType.KIST, SchedulerType.VANILLA),
        )
        if (LinuxTcpInfo.isFullKistEnabled()) {
            assertEquals(SchedulerType.KIST, selected)
        } else {
            // Default: do not pick KIST merely because python3 exists.
            assertEquals(SchedulerType.VANILLA, selected)
        }
    }

    @Test
    fun `KIST limit matches cwnd formula`() {
        val lim = KistMath.computeLimit(
            KistMath.SocketInfo(cwnd = 10, unacked = 2, mss = 1000, notSent = 0, outbufLen = 0),
            sockBufSizeFactor = 1.0,
        )
        // tcp_space = 8*1000=8000; extra = 10*1000*1 = 10000; sum = 18000
        assertEquals(18_000L, lim)
    }

    @Test
    fun `LinuxTcpInfo query on unbound socket is null or structured`() {
        // No connected fd required for API smoke; expect null without valid TCP fd.
        val s = java.net.Socket()
        val info = LinuxTcpInfo.query(s)
        // Unconnected socket typically fails TCP_INFO — null is OK.
        if (info != null) {
            assertTrue(info.sndMss > 0)
        }
        s.close()
    }

    @Test
    fun `KIST notsent too large clamps to zero`() {
        val lim = KistMath.computeLimit(
            KistMath.SocketInfo(cwnd = 2, unacked = 0, mss = 1000, notSent = 50_000, outbufLen = 0),
        )
        assertEquals(0L, lim)
    }

    @Test
    fun `platform caps for linux`() {
        val caps = PlatformNatives.capabilities(PlatformNatives.OsFamily.LINUX)
        assertTrue(caps.tcpInfoKist)
        assertTrue(caps.seccomp)
        assertTrue(caps.soOriginalDst)
    }

    @Test
    fun `WriteBudget KIST uses math`() {
        val b = WriteBudget(SchedulerType.KIST)
        b.refill(KistMath.SocketInfo(cwnd = 4, unacked = 0, mss = 500))
        // tcp=2000 extra=2000 → 4000
        assertEquals(4000, b.allow(10_000))
    }

    @Test
    fun `WriteBudget KIST refill accepts LinuxTcpInfo shaped SocketInfo`() {
        val b = WriteBudget(SchedulerType.KIST)
        val shaped = LinuxTcpInfo.Info(sndCwnd = 8, unacked = 1, sndMss = 1000, notSent = 0).toKist()
        b.refill(shaped)
        // tcp_space=7*1000=7000; extra=8*1000=8000 → 15000
        assertEquals(15_000, b.available)
    }
}
