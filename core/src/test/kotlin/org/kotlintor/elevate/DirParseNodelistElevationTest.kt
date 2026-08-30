package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.dir.AuthCertParse
import org.kotlintor.dir.Describe
import org.kotlintor.dir.DirServ
import org.kotlintor.dir.DlStatus
import org.kotlintor.dir.MicrodescParse
import org.kotlintor.dir.Nickname
import org.kotlintor.dir.NodeFamily
import org.kotlintor.dir.NodeList
import org.kotlintor.dir.NodeSelect
import org.kotlintor.dir.NsParse
import org.kotlintor.dir.ParseCommon
import org.kotlintor.dir.PolicyParse
import org.kotlintor.dir.RouterParse
import org.kotlintor.dir.Signing
import org.kotlintor.dir.Unparseable
import org.kotlintor.dir.VotingSchedule

/**
 * Elevates dirparse / nodelist / voting_schedule / dirserv / dlstatus L1 units.
 */
class DirParseNodelistElevationTest {
    @Test
    fun `parsecommon policy unparseable signing`() {
        val doc = "network-status-version 3\nvote-status consensus\n"
        assertTrue(ParseCommon.hasKeyword(doc, "vote-status"))
        assertEquals("3", ParseCommon.requireKeyword(doc, "network-status-version"))
        assertTrue(PolicyParse.isWellFormed("accept *:80"))
        Unparseable.clear()
        Unparseable.note("bad", "xxx")
        assertEquals(1, Unparseable.size())
        assertEquals(40, Signing.sha1DigestHex("hi").length)
        assertNull(AuthCertParse.tryParse("not a cert"))
    }

    @Test
    fun `nickname describe nodeselect family list`() {
        assertTrue(Nickname.isLegalNickname("Alice"))
        assertFalse(Nickname.isLegalNickname(""))
        assertTrue(
            Describe.node(
                nickname = "n",
                identityHex = "AA".repeat(20),
            ).isNotEmpty(),
        )
        val fam = NodeFamily.parse("\$" + "A".repeat(40) + " \$" + "B".repeat(40))
        assertTrue(fam != null && fam.members.size >= 2)
        assertEquals(0, NodeList.create().size())
        assertNull(NodeSelect.byBandwidth(emptyList()))
    }

    @Test
    fun `ns microdesc router voting dlstatus dirserv`() {
        assertTrue(NsParse.looksLikeConsensus("network-status-version 3\nvote-status consensus\n"))
        assertTrue(MicrodescParse.parseFamily("").isEmpty())
        assertNull(RouterParse.parse("router x 1.2.3.4 9001 0 0\n"))
        val vs = VotingSchedule.create(1_700_000_000L)
        assertTrue(vs.intervalSec > 0)
        assertTrue(DlStatus.create().isReady())
        assertEquals(0, DirServ.measuredBwCache().size)
    }
}
