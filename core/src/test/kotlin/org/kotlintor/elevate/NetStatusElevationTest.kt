package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.kotlintor.status.NetStatus

/**
 * Elevates `L1:core/mainloop/netstatus.c` toward D3.
 *
 * Evidence: NetStatus mirrors net_is_disabled / participation / state load-flush.
 */
class NetStatusElevationTest {
    @BeforeEach
    fun reset() = NetStatus.resetForTests()

    @Test
    fun `net_is_disabled and completely_disabled`() {
        assertFalse(NetStatus.netIsDisabled())
        NetStatus.options = NetStatus.Options(disableNetwork = true)
        assertTrue(NetStatus.netIsDisabled())
        assertTrue(NetStatus.netIsCompletelyDisabled())
        NetStatus.options = NetStatus.Options()
        NetStatus.hibernating = true
        assertTrue(NetStatus.netIsDisabled())
        assertFalse(NetStatus.netIsCompletelyDisabled())
        NetStatus.fullyHibernating = true
        assertTrue(NetStatus.netIsCompletelyDisabled())
    }

    @Test
    fun `note_user_activity starts participation`() {
        assertFalse(NetStatus.isParticipatingOnNetwork())
        NetStatus.noteUserActivity(1_000)
        assertTrue(NetStatus.isParticipatingOnNetwork())
        assertEquals(1_000, NetStatus.lastUserActivityTime())
        NetStatus.noteUserActivity(900) // never moves backwards
        assertEquals(1_000, NetStatus.lastUserActivityTime())
        NetStatus.noteUserActivity(1_100)
        assertEquals(1_100, NetStatus.lastUserActivityTime())
    }

    @Test
    fun `flush and load mainloop state`() {
        NetStatus.setNetworkParticipation(true)
        NetStatus.resetUserActivity(1_000)
        val st = NetStatus.MainloopState()
        NetStatus.flushToState(st, nowEpochSec = 1_000 + 120)
        assertEquals(0, st.dormant)
        assertEquals(2, st.minutesSinceUserActivity)

        NetStatus.resetForTests()
        NetStatus.options = NetStatus.Options(dormantOnFirstStartup = true)
        NetStatus.loadFromState(NetStatus.MainloopState(dormant = -1), nowEpochSec = 5_000)
        assertFalse(NetStatus.isParticipatingOnNetwork())

        NetStatus.resetForTests()
        NetStatus.options = NetStatus.Options(dormantCanceledByStartup = true)
        NetStatus.loadFromState(NetStatus.MainloopState(dormant = 1), nowEpochSec = 5_000)
        assertTrue(NetStatus.isParticipatingOnNetwork())
        assertEquals(5_000, NetStatus.lastUserActivityTime())
    }

    @Test
    fun `clock jump adjusts last activity`() {
        NetStatus.resetUserActivity(1_000)
        NetStatus.noteClockJumped(50)
        assertEquals(1_050, NetStatus.lastUserActivityTime())
    }
}
