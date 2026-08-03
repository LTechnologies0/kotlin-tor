package org.kotlintor.elevate

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.link.ChannelSchedState
import org.kotlintor.link.ChannelSchedulerPending
import org.kotlintor.link.ChannelTable
import org.kotlintor.link.ConnectionTable
import org.kotlintor.link.ConnectionType
import org.kotlintor.link.OrChannel

class ListenerPendingSchedulerElevationTest {
    @Test
    fun `OR DIR CONTROL listeners register in ConnectionTable`() {
        ConnectionTable.clear()
        val orL = ConnectionTable.newListener("127.0.0.1", 9001, ConnectionType.OR)
        orL.markOpen()
        val dirL = ConnectionTable.newListener("127.0.0.1", 9030, ConnectionType.DIR)
        dirL.markOpen()
        val ctrlL = ConnectionTable.newListener("127.0.0.1", 9051, ConnectionType.CONTROL)
        ctrlL.markOpen()
        val dirClient = ConnectionTable.newDir("10.0.0.1", 44321, purpose = "http")
        dirClient.resource = "/tor/status-vote/current/consensus"
        dirClient.markOpen()
        val ctrl = ConnectionTable.newControl("127.0.0.1", 50000)
        ctrl.authenticated = true
        ctrl.markOpen()
        assertEquals(3, ConnectionTable.byType(ConnectionType.LISTENER).size)
        assertEquals(1, ConnectionTable.byType(ConnectionType.DIR).size)
        assertEquals(1, ConnectionTable.byType(ConnectionType.CONTROL).size)
        assertTrue(ConnectionTable.countOpen() >= 5)
        ConnectionTable.clear()
    }

    @Test
    fun `ChannelSchedulerPending drains registered flush hooks`() = runBlocking {
        ChannelSchedulerPending.clear()
        ChannelTable.clear()
        val ch = ChannelTable.register(OrChannel(remoteAddr = "1.1.1.1", remotePort = 9001))
        ch.markOpen()
        ch.queueOut(ByteArray(514))
        var flushed = 0
        ChannelSchedulerPending.register(ch) {
            val p = ch.popOut()
            if (p != null) {
                flushed++
                1
            } else {
                0
            }
        }
        ChannelSchedulerPending.notePending(ch)
        assertEquals(1, ChannelSchedulerPending.pendingCount())
        assertEquals(ChannelSchedState.PENDING, ch.schedState)
        val n = ChannelSchedulerPending.drain(maxChannels = 4)
        assertEquals(1, n)
        assertEquals(1, flushed)
        assertEquals(0, ch.outbufBytes)
        ChannelSchedulerPending.unregister(ch.globalId)
        ChannelTable.remove(ch.globalId)
        ChannelSchedulerPending.clear()
    }
}
