package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.link.OrChannel
import org.kotlintor.link.ChannelSchedState
import org.kotlintor.link.ChannelState
import org.kotlintor.link.ChannelTable
import org.kotlintor.link.ConnectionTable
import org.kotlintor.link.EdgeLinkedPair
import org.kotlintor.link.KistMath

class ChannelOutbufLinkedElevationTest {
    @Test
    fun `channel outbuf queue and sched state`() {
        ChannelTable.clear()
        val ch = ChannelTable.register(OrChannel(remoteAddr = "1.2.3.4", remotePort = 9001))
        ch.markOpen()
        assertEquals(ChannelState.OPEN, ch.state)
        assertTrue(ch.hasBeenOpen)
        val cell = ByteArray(514) { 1 }
        assertTrue(ch.queueOut(cell))
        assertEquals(514, ch.outbufBytes)
        assertEquals(1, ch.cellsQueued)
        assertEquals(ChannelSchedState.PENDING, ch.schedState)
        val popped = ch.popOut()!!
        assertEquals(514, popped.size)
        assertEquals(0, ch.outbufBytes)
        assertEquals(1, ch.cellsWritten)
        ch.bytesWrittenAccount(100)
        assertEquals(2, ch.cellsWritten)
        assertEquals(614, ch.bytesWritten)
        ch.markClosed()
        ChannelTable.remove(ch.globalId)
        assertEquals(0, ChannelTable.count())
    }

    @Test
    fun `KistMath uses outbufLen`() {
        val lim = KistMath.computeLimit(
            KistMath.SocketInfo(cwnd = 10, unacked = 2, mss = 1460, notSent = 0, outbufLen = 5000),
            sockBufSizeFactor = 1.0,
        )
        // tcpSpace = 8*1460 = 11680; extra = 10*1460 - 5000 = 9600; sum = 21280
        assertEquals(21_280L, lim)
    }

    @Test
    fun `EdgeLinkedPair AP EXIT linked`() {
        ConnectionTable.clear()
        val pair = EdgeLinkedPair.open(
            clientHost = "127.0.0.1",
            clientPort = 45000,
            destHost = "example.com",
            destPort = 443,
            circId = 9,
            streamId = 3,
            socksUser = "alice",
        )
        assertEquals(pair.exit.id, pair.entry.linkedConnId)
        assertEquals(pair.entry.id, pair.exit.linkedConnId)
        assertEquals("example.com:443", pair.entry.originalDest)
        assertEquals(2, ConnectionTable.countOpen())
        EdgeLinkedPair.close(pair)
        assertEquals(0, ConnectionTable.countOpen())
    }
}
