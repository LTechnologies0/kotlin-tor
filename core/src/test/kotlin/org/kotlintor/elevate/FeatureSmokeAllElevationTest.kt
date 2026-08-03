package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.api.TorApi
import org.kotlintor.cell.Cell
import org.kotlintor.cell.CellCommand
import org.kotlintor.cell.CircuitPurpose
import org.kotlintor.circuit.CircuitList
import org.kotlintor.config.ListenSpec
import org.kotlintor.config.TorConfig
import org.kotlintor.config.TorrcParser
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
import org.kotlintor.hs.HsIntroPointTable
import org.kotlintor.hs.HsMetrics
import org.kotlintor.hs.HsOpts
import org.kotlintor.hs.HsSys
import org.kotlintor.keymgt.LoadKey
import org.kotlintor.link.Control0Peek
import org.kotlintor.metrics.MetricsSys
import org.kotlintor.net.HaproxyProxyHeader
import org.kotlintor.or.CachedDir
import org.kotlintor.or.ControlCmdArgs
import org.kotlintor.or.DescStore
import org.kotlintor.or.OrHandshakeState
import org.kotlintor.or.SocksRequest
import org.kotlintor.or.TorVersion
import org.kotlintor.or.VarCell
import org.kotlintor.relay.BwHist
import org.kotlintor.relay.RelayConfigView
import org.kotlintor.relay.RelayFindAddr
import org.kotlintor.relay.RelayHandshake
import org.kotlintor.relay.RelayMetrics
import org.kotlintor.relay.RelayPeriodic
import org.kotlintor.relay.RelaySys
import org.kotlintor.relay.RouterMode
import org.kotlintor.relay.TransportConfig
import org.kotlintor.status.HeartbeatStatus
import org.kotlintor.trunnel.LinkHandshakeTrunnel
import org.kotlintor.trunnel.NetinfoTrunnel
import org.kotlintor.trunnel.PwBoxTrunnel
import org.kotlintor.trunnel.SubprotoRequestTrunnel
import org.kotlintor.util.u32be
import java.nio.file.Files
import kotlin.io.path.createTempDirectory

/**
 * End-to-end smoke of features elevated in the recent inventory batches.
 * Fails loud if any surface regresses.
 */
class FeatureSmokeAllElevationTest {
    @Test
    fun `smoke every elevated surface`() {
        val data = createTempDirectory("ktor-feature-smoke")

        // --- Tor API embed ---
        val api = TorApi.newConfiguration()
        api.dataDirectory = data
        api.addTorrcLine("SocksPort 9050")
        api.addTorrcLine("ConfluxEnabled 1")
        api.addTorrcLine("DormantClientTimeout 7200")
        api.addTorrcLine("HTTPProxy 10.0.0.1:8080")
        api.addTorrcLine("V3AuthVotingInterval 300")
        api.addTorrcLine("TestingEnableCellStatsEvent 1")
        val cfg = api.buildConfig()
        assertEquals(data, cfg.dataDirectory)
        assertTrue(cfg.runtime.confluxEnabled)
        assertEquals(7200L, cfg.runtime.dormantClientTimeoutSec)
        assertEquals("10.0.0.1:8080", cfg.runtime.httpProxy)
        assertEquals(300, cfg.runtime.v3AuthVotingIntervalSec)
        assertTrue(cfg.runtime.testingEnableCellStatsEvent)
        assertTrue(TorApi.version().startsWith("0.1.0"))

        // --- LoadKey ---
        val keys = data.resolve("keys")
        val ed1 = LoadKey.loadOrCreateEd25519Identity(keys)
        val ed2 = LoadKey.loadOrCreateEd25519Identity(keys)
        assertTrue(ed1.publicKey.contentEquals(ed2.publicKey))
        assertTrue(Files.isRegularFile(keys.resolve("ed25519_master_id_secret_key")))

        // --- HAProxy + control0 ---
        val proxy = HaproxyProxyHeader.formatProxyHeaderLine("198.51.100.9", 443)!!
        val parsed = HaproxyProxyHeader.parseProxyHeaderLine(proxy)!!
        assertEquals("TCP4", parsed.family)
        assertEquals(443, parsed.dstPort)
        assertTrue(Control0Peek.hasControl0Command(byteArrayOf(5, 0, 0)))
        assertFalse(Control0Peek.hasControl0Command("GETINFO".toByteArray()))

        // --- Dirauth / dirclient ---
        val authCfg = cfg.copy(
            clientOnly = false,
            authoritativeDirectory = true,
            v3AuthoritativeDirectory = true,
            orPort = ListenSpec("127.0.0.1", 9001),
        )
        assertTrue(DirAuthOptions.fromTorConfig(authCfg).enabled())
        assertTrue(DirAuthSys.shouldRunPublishLoop(authCfg))
        val timing = DirAuthSys.timingFromConfig(authCfg)
        assertTrue(timing.voteSeconds + timing.distSeconds < timing.voteIntervalSec)
        assertTrue(DirClientModes.fetchesFromAuthorities(authCfg))
        assertTrue(RouterMode.dirServerMode(authCfg))

        // --- Dirparse ---
        val doc = "network-status-version 3\nvote-status consensus\n"
        assertEquals("3", DirParseCommon.requireKeyword(doc, "network-status-version"))
        PolicyParse.parseExitPolicyLines(listOf("accept *:80", "reject *:*"))
        UnparseableDump.clear()
        UnparseableDump.note("smoke", "bad-doc")
        assertEquals(1, UnparseableDump.size())
        assertEquals(40, DirSigning.sha1DigestHex("x").length)
        assertEquals(0x05, TorCert.TYPE_SIGNING_V_TLS_CERT)
        assertTrue(runCatching { AuthCertParse.parse("not-a-cert") }.isFailure)

        // --- HS ---
        assertFalse(HsSys.enabled(cfg))
        assertEquals(0, HsOpts.fromTorConfig(cfg).services.size)
        assertTrue(HsCommon.timePeriodNum() > 0)
        val dos = HsDosDefense(ratePerSec = 5, burst = 10)
        repeat(3) { assertTrue(dos.noteIntroduce("svc-a")) }
        val intros = HsIntroPointTable()
        intros.noteEstablished("deadbeef")
        intros.noteIntroduce("deadbeef")
        assertEquals(1L, intros.get("DEADBEEF")?.introduceCount)
        HsMetrics.reset()
        HsMetrics.noteDescFetch()
        HsMetrics.noteIntroReceived()
        HsMetrics.noteIntroRejected()
        assertEquals(1, HsMetrics.snapshot()["hs_desc_fetches"])
        assertTrue(HsControl.descEventCreated("x.onion", "blind").contains("HS_DESC CREATED"))
        assertTrue(HsControl.hsPostAccepted("body", "abc.onion"))
        assertTrue(HsControl.hsFetchAccepted("ab".repeat(32)))

        // --- Relay ---
        val relayCfg = authCfg.copy(nickname = "SmokeRelay", address = "203.0.113.50", publishServerDescriptor = true)
        assertEquals("SmokeRelay", RelayConfigView.fromTorConfig(relayCfg).nickname)
        assertEquals("203.0.113.50", RelayFindAddr.addressToPublish(relayCfg))
        assertTrue(RelaySys.shouldRunRelay(relayCfg))
        assertTrue(RelaySys.shouldPublishDescriptor(relayCfg))
        assertEquals(18 * 3600L, RelayPeriodic.descriptorRepublishIntervalSec(relayCfg))
        RelayMetrics.reset()
        RelayMetrics.noteCell()
        RelayMetrics.noteCircuit()
        RelayMetrics.noteExitStream()
        assertEquals(1L, RelayMetrics.snapshot()["relay_cells"])
        assertEquals(listOf(3, 4, 5), RelayHandshake.advertisedLinkVersions(relayCfg))
        assertTrue(RelayHandshake.supportsNtor(relayCfg))
        assertNotNull(TransportConfig.fromTorConfig(relayCfg))

        // --- Metrics + trunnel ---
        assertFalse(MetricsSys.enabled(cfg))
        assertTrue(MetricsSys.snapshot().containsKey("relay_cells"))
        val vers = LinkHandshakeTrunnel.parseVersions(LinkHandshakeTrunnel.versionsPayload(listOf(3, 4, 5)))
        assertEquals(listOf(3, 4, 5), vers)
        val netCell = Cell(0, CellCommand.NETINFO, u32be(1_700_000_001L) + ByteArray(505))
        assertEquals(1_700_000_001L, NetinfoTrunnel.timestampFromCell(netCell))
        assertEquals("2", SubprotoRequestTrunnel.parse(SubprotoRequestTrunnel.encode(mapOf("Relay" to "2")))["Relay"])
        assertFalse(PwBoxTrunnel.supported())

        // --- CircuitList / status / bw_array ---
        CircuitList.clear()
        CircuitList.registerOrigin(11, CircuitPurpose.GENERAL)
        CircuitList.registerOr(12, isExit = true)
        CircuitList.markDirty(11)
        assertEquals(1, CircuitList.dirtyCircuits().size)
        assertEquals(1, CircuitList.countOrigins())
        HeartbeatStatus.resetClock(0)
        val hb = HeartbeatStatus.format(1, 2, true, 1, 1, nowMs = 5_000)
        assertTrue(hb.contains("uptime=5s"))
        assertEquals(1, HeartbeatStatus.heartbeatCount())
        assertEquals(5, BwHist.Slot(5, 0, 0, 0).toBwArray().read)

        // --- OrStruct mirrors ---
        assertTrue(CachedDir("body").dir.isNotEmpty())
        val store = DescStore()
        store.store("aa", "desc")
        assertEquals("desc", store.lookup("AA"))
        assertEquals(443, SocksRequest(1, "ex.com", 443).port)
        assertEquals("0.4.8-stable", TorVersion.parse("0.4.8")!!.toString())
        assertFalse(OrHandshakeState().receivedNetinfo)
        assertEquals(0, ControlCmdArgs().args.size)
        val vc = VarCell(0, CellCommand.VERSIONS.id, byteArrayOf(0, 4))
        assertEquals(0L, vc.circId)

        // --- Full torrc round-trip of runtime keys ---
        val rt = TorrcParser.parse(
            """
            DataDirectory $data
            DirCache 0
            KISTSchedRunInterval 7
            ExtendByEd25519ID 0
            LeaveStreamsUnattached 1
            MaxHSDirCacheBytes 1048576
            Socks5Proxy 127.0.0.1:1080
            TCPProxyProtocol haproxy
            TestingV3AuthInitialVotingInterval 10
            """.trimIndent(),
            data,
        )
        assertFalse(rt.runtime.dirCache)
        assertEquals(7, rt.runtime.kistSchedRunIntervalMs)
        assertFalse(rt.runtime.extendByEd25519Id)
        assertTrue(rt.runtime.leaveStreamsUnattached)
        assertEquals(1_048_576L, rt.runtime.maxHsDirCacheBytes)
        assertEquals("127.0.0.1:1080", rt.runtime.socks5Proxy)
        assertEquals("haproxy", rt.runtime.tcpProxyProtocol)
        assertEquals(10, rt.runtime.testingV3AuthInitialVotingInterval)

        CircuitList.clear()
        UnparseableDump.clear()
        HsMetrics.reset()
        RelayMetrics.reset()
    }
}
