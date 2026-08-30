package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.cell.RelayCommand
import org.kotlintor.hs.Ed25519Cert
import org.kotlintor.trunnel.CellEstablishIntro
import org.kotlintor.trunnel.CellIntroduce1
import org.kotlintor.trunnel.CellRendezvous
import org.kotlintor.trunnel.ChannelpaddingNegotiation
import org.kotlintor.trunnel.CircpadNegotiation
import org.kotlintor.trunnel.CongestionControl as TrunnelCongestionControl
import org.kotlintor.trunnel.Extension
import org.kotlintor.trunnel.FlowControlCells
import org.kotlintor.trunnel.LinkHandshake
import org.kotlintor.trunnel.Netinfo
import org.kotlintor.trunnel.Pwbox
import org.kotlintor.trunnel.SendmeCell
import org.kotlintor.trunnel.Socks5
import org.kotlintor.trunnel.SubprotoRequest

/**
 * Elevates remaining L1 trunnel units to D3 naming primaries.
 */
class TrunnelElevationTest {
    @Test
    fun `link netinfo subproto pwbox`() {
        val v = LinkHandshake.versionsPayload(listOf(3, 4, 5))
        assertEquals(listOf(3, 4, 5), LinkHandshake.parseVersions(v))
        assertEquals(4, Netinfo.encodeTimestamp(1L).size)
        assertEquals(mapOf("Relay" to "1"), SubprotoRequest.parse(SubprotoRequest.encode(mapOf("Relay" to "1"))))
        assertFalse(Pwbox.supported())
    }

    @Test
    fun `padding cells flow sendme socks congestion extension cert`() {
        assertTrue(ChannelpaddingNegotiation.known())
        assertTrue(CircpadNegotiation.encodeStart().isNotEmpty())
        assertTrue(TrunnelCongestionControl.known())
        assertEquals(Ed25519Cert.TYPE_IDENTITY_V_SIGNING, 0x04)
        assertTrue(Extension.cgoRequest().body.isNotEmpty())
        assertTrue(FlowControlCells.known().contains(RelayCommand.XON))
        assertEquals("ESTABLISH_INTRO", CellEstablishIntro.COMMAND)
        assertEquals("INTRODUCE1", CellIntroduce1.COMMAND)
        assertEquals("RENDEZVOUS1", CellRendezvous.COMMAND)
        assertEquals(RelayCommand.SENDME, SendmeCell.command())
        assertTrue(Socks5.versionOk(5))
    }
}
