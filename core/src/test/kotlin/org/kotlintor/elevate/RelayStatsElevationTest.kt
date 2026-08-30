package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.dir.PredictPorts
import org.kotlintor.relay.BwHist
import org.kotlintor.relay.Hibernate
import org.kotlintor.relay.HibernateAccounting
import org.kotlintor.relay.RelaySelfTest
import org.kotlintor.relay.RepHist
import org.kotlintor.relay.RouterKeys
import org.kotlintor.relay.Selftest
import org.kotlintor.stats.ConnStats
import org.kotlintor.stats.GeoipStats
import java.nio.file.Files

/**
 * Elevates relay selftest / hibernate / routerkeys and stats L1 units.
 */
class RelayStatsElevationTest {
    @Test
    fun `bwhist selftest routerkeys`() {
        BwHist.clear()
        BwHist.noteBytesRead(100)
        BwHist.noteBytesWritten(200)
        assertTrue(BwHist.getBandwidthLines().contains("read-history"))
        val st = Selftest.create()
        assertFalse(st.orportSeemsReachable())
        st.foundReachable(RelaySelfTest.Family.IPV4)
        assertTrue(st.orportSeemsReachable())
        val dir = Files.createTempDirectory("ktor-rk")
        val keys = RouterKeys.rotator(dir).loadOrGenerate()
        assertEquals(32, keys.current.publicKey.size)
    }

    @Test
    fun `hibernate rephist connstats geoip predict`() {
        val h = Hibernate.accounting(soft = 100, hard = 200)
        h.note(read = 50, written = 60)
        assertEquals(HibernateAccounting.State.SOFT, h.state())
        RepHist.clear()
        RepHist.noteCreate("aa")
        assertEquals(1, RepHist.forRelay("aa").nCreated)
        ConnStats.init()
        ConnStats.noteOrConnBytes(1L, 10, 20)
        assertTrue(ConnStats.format().contains("conn-bi-direct"))
        GeoipStats.setEntryEnabled(true)
        assertTrue(GeoipStats.entryEnabled())
        assertTrue(GeoipStats.formatEntryStats().isNotEmpty())
        PredictPorts.clear()
        PredictPorts.noteUse(443)
        assertEquals(listOf(443), PredictPorts.predicted())
    }
}
