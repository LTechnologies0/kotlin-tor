package org.kotlintor.dir

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.relay.BwHist
import org.kotlintor.relay.RelaySelfTest

class ProcessDescsAuthModeBwHistTest {
    @Test
    fun `authmode predicates`() {
        val off = AuthModeOptions()
        assertFalse(AuthMode.isAuthority(off))
        val on = AuthModeOptions(authoring = true, bridgeAuthority = true)
        assertTrue(AuthMode.isBridge(on))
        assertTrue(AuthMode.handlesDescs(on, AuthMode.PURPOSE_BRIDGE))
        assertFalse(AuthMode.handlesDescs(on, AuthMode.PURPOSE_GENERAL))
    }

    @Test
    fun `process descs reject and nickname pin`() {
        val p = ProcessDescs()
        p.loadApprovedRouters(
            """
            !reject aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            NiceRelay bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
            """.trimIndent(),
        )
        val rej = p.addDescriptor(
            ProcessDescs.Descriptor("x", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        )
        assertEquals(ProcessDescs.Added.REJECTED, rej.first)
        val badNick = p.addDescriptor(
            ProcessDescs.Descriptor("NiceRelay", "cccccccccccccccccccccccccccccccccccccccc"),
        )
        assertEquals(ProcessDescs.Added.REJECTED, badNick.first)
        val ok = p.addDescriptor(
            ProcessDescs.Descriptor(
                "NiceRelay",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                publishedEpochSec = 10,
                body = "router NiceRelay",
            ),
        )
        assertEquals(ProcessDescs.Added.ADDED, ok.first)
    }

    @Test
    fun `bwhist and selftest`() {
        BwHist.clear()
        BwHist.noteBytesRead(1000)
        BwHist.noteBytesWritten(2000)
        assertTrue(BwHist.bandwidthAssess() >= 3000)
        assertTrue(BwHist.getBandwidthLines().contains("write-history"))
        val st = RelaySelfTest()
        assertFalse(st.orportSeemsReachable())
        st.foundReachable()
        assertTrue(st.allOrportsSeemReachable())
        st.performBandwidthTest(2, 100)
        assertEquals(200, st.bandwidthTestTotal())
    }
}
