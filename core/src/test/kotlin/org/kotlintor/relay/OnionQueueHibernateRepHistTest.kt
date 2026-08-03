package org.kotlintor.relay

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class OnionQueueHibernateRepHistTest {
    @Test
    fun `onion queue drops when full and expires`() {
        val q = OnionQueue(maxPending = 2, maxDelayMs = 10)
        assertTrue(q.tryEnqueue(1, byteArrayOf(1)))
        assertTrue(q.tryEnqueue(2, byteArrayOf(2)))
        assertFalse(q.tryEnqueue(3, byteArrayOf(3)))
        assertNotNull(q.poll())
    }

    @Test
    fun `hibernate soft and hard`() {
        val h = HibernateAccounting(softLimitBytes = 100, hardLimitBytes = 200, intervalSec = 3600)
        h.note(read = 50, written = 40)
        assertEquals(HibernateAccounting.State.LIVE, h.state())
        h.note(read = 20)
        assertEquals(HibernateAccounting.State.SOFT, h.state())
        assertFalse(h.acceptsNewConnections())
        assertTrue(h.acceptsData())
        h.note(written = 100)
        assertEquals(HibernateAccounting.State.HARD, h.state())
        assertFalse(h.acceptsData())
    }

    @Test
    fun `rephist counters`() {
        RepHist.clear()
        RepHist.noteCreate("aa")
        RepHist.noteSuccess("aa")
        RepHist.noteBytes("aa", 10, 20)
        assertEquals(1, RepHist.forRelay("aa").nSucceeded)
        assertEquals(20, RepHist.forRelay("aa").bytesWritten)
    }
}
