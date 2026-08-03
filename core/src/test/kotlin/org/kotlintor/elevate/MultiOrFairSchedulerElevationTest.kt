package org.kotlintor.elevate

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.link.ChannelSchedulerPending
import org.kotlintor.link.ChannelTable
import org.kotlintor.link.OrChannel

class MultiOrFairSchedulerElevationTest {
    @Test
    fun `drainFair balances multi-OR channel flush counts`() = runBlocking {
        ChannelSchedulerPending.clear()
        ChannelTable.clear()
        val channels = (1..4).map { i ->
            ChannelTable.register(OrChannel(remoteAddr = "1.0.0.$i", remotePort = 9000 + i)).also { ch ->
                ch.markOpen()
                repeat(3) { ch.queueOut(ByteArray(64)) }
                ChannelSchedulerPending.register(ch) {
                    val p = ch.popOut()
                    if (p != null) 1 else 0
                }
                ChannelSchedulerPending.notePending(ch)
            }
        }
        repeat(12) {
            ChannelSchedulerPending.drainFair(maxChannels = 4)
        }
        assertEquals(4, ChannelSchedulerPending.registeredCount())
        val counts = channels.map { ChannelSchedulerPending.flushCount(it.globalId) }
        assertTrue(counts.all { it >= 1 }, "counts=$counts")
        assertTrue(
            ChannelSchedulerPending.fairnessSpread() <= 2,
            "spread=${ChannelSchedulerPending.fairnessSpread()} counts=$counts",
        )
        channels.forEach {
            ChannelSchedulerPending.unregister(it.globalId)
            ChannelTable.remove(it.globalId)
        }
        ChannelSchedulerPending.clear()
    }
}
