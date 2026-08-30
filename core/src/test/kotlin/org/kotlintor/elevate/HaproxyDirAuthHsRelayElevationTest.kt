package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.config.ListenSpec
import org.kotlintor.config.TorConfig
import org.kotlintor.dir.AuthCertParse
import org.kotlintor.dir.DirAuthOptions
import org.kotlintor.dir.DirAuthSys
import org.kotlintor.dir.DirClientModes
import org.kotlintor.dir.DirParseCommon
import org.kotlintor.dir.DirSigning
import org.kotlintor.dir.PolicyParse
import org.kotlintor.dir.TorCert
import org.kotlintor.dir.UnparseableDump
import org.kotlintor.hs.HsCommon
import org.kotlintor.hs.HsControl
import org.kotlintor.hs.HsDosDefense
import org.kotlintor.hs.HsIntroFsm
import org.kotlintor.hs.HsIntroPointTable
import org.kotlintor.hs.HsMetrics
import org.kotlintor.hs.HsOpts
import org.kotlintor.hs.HsSys
import org.kotlintor.link.Control0Peek
import org.kotlintor.net.HaproxyProxyHeader
import org.kotlintor.relay.RelayConfigView
import org.kotlintor.relay.RelayFindAddr
import org.kotlintor.relay.RelayHandshake
import org.kotlintor.relay.RelayHandshakeState
import org.kotlintor.relay.RelayMetrics
import org.kotlintor.relay.RelayPeriodic
import org.kotlintor.relay.RelaySys
import org.kotlintor.relay.RouterMode
import org.kotlintor.relay.TransportConfig
import java.nio.file.Path

/**
 * Elevates inventory rows (D0→D1):
 * - L1:core/proto/proto_haproxy.c, proto_control0.c
 * - L1:feature/dirauth/dirauth_{config,sys,periodic}.c / L2:dirauth_options_t
 * - L1:feature/dirclient/dirclient_modes.c
 * - L1:feature/dirparse/{parsecommon,policy_parse,unparseable,sigcommon,signing,authcert_parse}.c
 * - L1:feature/hs/hs_{common,config,control,dos,ident,intropoint,metrics,metrics_entry,sys}.c
 * - L1:feature/nodelist/torcert.c
 * - L1:feature/relay/relay_{config,find_addr,sys,periodic,metrics,handshake}.c, transport_config.c
 */
class HaproxyDirAuthHsRelayElevationTest {
    private val dataDir: Path = Path.of("/tmp/ktor-elevate-test")

    @Test
    fun `haproxy proxy header format and parse`() {
        val line = HaproxyProxyHeader.formatProxyHeaderLine("1.2.3.4", 9001)!!
        assertTrue(line.startsWith("PROXY TCP4 "))
        val p = HaproxyProxyHeader.parseProxyHeaderLine(line)!!
        assertEquals("TCP4", p.family)
        assertEquals("1.2.3.4", p.dst)
        assertEquals(9001, p.dstPort)
    }

    @Test
    fun `control0 peek rejects obsolete framing`() {
        // C Tor: uint16 cmd at offset 2, network order, ≤ 0x14
        assertTrue(Control0Peek.hasControl0Command(byteArrayOf(0, 0, 0, 1)))
        assertTrue(Control0Peek.hasControl0Command(byteArrayOf(0, 0, 0, 0x14)))
        assertFalse(Control0Peek.hasControl0Command(byteArrayOf(0, 0, 0, 0x15)))
        assertFalse(Control0Peek.hasControl0Command(byteArrayOf('G'.code.toByte())))
        assertFalse(Control0Peek.hasControl0Command("GETINFO".toByteArray()))
        assertTrue(Control0Peek.rejectReason().contains("control"))
    }

    @Test
    fun `dirauth options and client modes`() {
        val c = TorConfig(
            dataDirectory = dataDir,
            clientOnly = false,
            authoritativeDirectory = true,
            v3AuthoritativeDirectory = true,
            orPort = ListenSpec("127.0.0.1", 9050),
        )
        val opts = DirAuthOptions.fromTorConfig(c)
        assertTrue(opts.enabled())
        assertTrue(DirAuthSys.shouldRunPublishLoop(c))
        val timing = DirAuthSys.timingFromConfig(c)
        assertEquals(300, timing.voteIntervalSec)
        assertTrue(DirClientModes.mustUseBegindir(c.copy(orPort = null, authoritativeDirectory = false)))
        assertTrue(DirClientModes.fetchesFromAuthorities(c))
    }

    @Test
    fun `dirparse helpers and torcert constants`() {
        val doc = "network-status-version 3\nvote-status vote\n"
        assertEquals("3", DirParseCommon.requireKeyword(doc, "network-status-version"))
        val pol = PolicyParse.parseExitPolicyLines(listOf("reject *:*"))
        assertNotNull(pol)
        UnparseableDump.note("bad", "garbage")
        assertEquals("garbage", UnparseableDump.get("bad"))
        UnparseableDump.clear()
        assertTrue(DirSigning.sha1DigestHex("abc").length == 40)
        assertEquals(0x04, TorCert.TYPE_IDENTITY_V_SIGNING)
        // AuthCertParse delegates; empty parse must throw
        runCatching { AuthCertParse.parse("") }.exceptionOrNull().let { assertNotNull(it) }
    }

    @Test
    fun `hs common config dos intro metrics control`() {
        val c = TorConfig(dataDirectory = dataDir)
        assertFalse(HsSys.enabled(c))
        assertEquals(0, HsOpts.fromTorConfig(c).services.size)
        assertTrue(HsCommon.timePeriodNum() > 0)
        val dos = HsDosDefense(ratePerSec = 2, burst = 3, enabled = true)
        assertTrue(dos.noteIntroduce("svc"))
        assertTrue(dos.noteIntroduce("svc"))
        val intro = HsIntroPointTable()
        intro.beginEstablish("aa")
        intro.noteEstablished("aa")
        intro.noteIntroduce("aa")
        assertEquals(1, intro.get("aa")?.introduceCount)
        assertEquals(HsIntroFsm.INTRO_RECEIVED, intro.get("aa")?.fsm)
        HsMetrics.reset()
        HsMetrics.noteIntroReceived()
        assertEquals(1, HsMetrics.snapshot()["hs_intro_received"])
        val ev = HsControl.descEventRequested("onion", "blinded", "hsdir")
        assertTrue(ev.startsWith("HS_DESC REQUESTED"))
        assertTrue(HsControl.hsPostAccepted("body", "onion.onion"))
    }

    @Test
    fun `relay config findaddr metrics transport`() {
        val c = TorConfig(
            dataDirectory = dataDir,
            clientOnly = false,
            orPort = ListenSpec("127.0.0.1", 9001),
            nickname = "KtorTest",
            address = "203.0.113.10",
            publishServerDescriptor = true,
            serverTransportListenAddr = listOf("obfs4 0.0.0.0:443"),
        )
        val view = RelayConfigView.fromTorConfig(c)
        assertEquals("KtorTest", view.nickname)
        assertTrue(view.validate().isEmpty())
        assertEquals("203.0.113.10", RelayFindAddr.addressToPublish(c))
        assertTrue(RelaySys.shouldRunRelay(c))
        RelaySys.init(c)
        assertTrue(RelaySys.isStarted())
        assertTrue(RelaySys.shouldPublishDescriptor(c))
        assertEquals(18 * 3600, RelayPeriodic.descriptorRepublishIntervalSec(c))
        assertTrue(RelayPeriodic.scheduleHints(c).containsKey("metrics_flush_sec"))
        RelayMetrics.reset()
        RelayMetrics.noteCell()
        RelayMetrics.noteDescriptorPublished()
        assertEquals(1L, RelayMetrics.snapshot()["relay_cells"])
        assertTrue(RelayMetrics.exportPrometheus().contains("relay_descriptors_published"))
        assertEquals(listOf(3, 4, 5), RelayHandshake.advertisedLinkVersions(c))
        RelayHandshake.noteState(RelayHandshakeState.OPEN)
        assertTrue(RelayHandshake.lastStates().contains(RelayHandshakeState.OPEN))
        val tc = TransportConfig.fromTorConfig(c)
        assertEquals(1, tc.parsedListenAddrs().size)
        assertEquals("obfs4", tc.parsedListenAddrs().first().transport)
        assertEquals(443, tc.parsedListenAddrs().first().port)
        RouterMode.setAdvertisedServerMode(false)
        assertFalse(RouterMode.advertisedServerMode(c))
        RouterMode.setAdvertisedServerMode(null)
    }
}