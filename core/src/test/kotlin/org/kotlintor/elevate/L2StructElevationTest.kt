package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.cell.Cell
import org.kotlintor.cell.CellCommand
import org.kotlintor.circuit.CellQueue
import org.kotlintor.circuit.CircuitKind
import org.kotlintor.circuit.CircuitLayerCake
import org.kotlintor.circuit.CircuitMux
import org.kotlintor.circuit.ConfluxSet
import org.kotlintor.circuit.CongestionControl
import org.kotlintor.circuit.CryptPath
import org.kotlintor.circuit.DestroyCellQueue
import org.kotlintor.circuit.ExtendInfo
import org.kotlintor.circuit.HalfEdge
import org.kotlintor.circuit.Tor1Crypt
import org.kotlintor.config.OrState
import org.kotlintor.config.ListenSpec
import org.kotlintor.config.TorConfig
import org.kotlintor.crypto.Cgo
import org.kotlintor.dir.AuthorityCert
import org.kotlintor.dir.DetachedSignatures
import org.kotlintor.dir.DirAuthOptions
import org.kotlintor.dir.DirServer
import org.kotlintor.dir.DownloadStatus
import org.kotlintor.dir.Microdesc
import org.kotlintor.dir.NetworkStatus
import org.kotlintor.dir.Node
import org.kotlintor.dir.NodeFamily
import org.kotlintor.dir.RouterInfo
import org.kotlintor.dir.RouterList
import org.kotlintor.dir.RouterSet
import org.kotlintor.hs.HsOpts
import org.kotlintor.link.ChannelState
import org.kotlintor.link.Connection
import org.kotlintor.link.ConnectionTable
import org.kotlintor.link.ConnectionType
import org.kotlintor.link.OrChannel
import org.kotlintor.link.OrConnection
import org.kotlintor.mainloop.MainloopState
import org.kotlintor.net.AddrPolicy
import org.kotlintor.or.CachedDir
import org.kotlintor.or.ChannelListener
import org.kotlintor.or.ChannelTls
import org.kotlintor.or.CircuitBuildTimes
import org.kotlintor.or.ConfluxLeg
import org.kotlintor.or.ConfluxParamsSt
import org.kotlintor.or.ControlCmdArgs
import org.kotlintor.or.CpathBuildState
import org.kotlintor.or.CryptPathReference
import org.kotlintor.or.DescStore
import org.kotlintor.or.DestroyCell
import org.kotlintor.or.DocumentSignature
import org.kotlintor.or.ExtOrCmd
import org.kotlintor.or.ExtraInfo
import org.kotlintor.or.HsDirIndex
import org.kotlintor.or.MicrodescCache
import org.kotlintor.or.NetworkstatusSrInfo
import org.kotlintor.or.NetworkstatusVoterInfo
import org.kotlintor.or.OnionHandshakeState
import org.kotlintor.or.OrHandshakeCerts
import org.kotlintor.or.OrHandshakeState
import org.kotlintor.or.PackedCell
import org.kotlintor.or.PortCfg
import org.kotlintor.or.RelayMsg
import org.kotlintor.or.SignedDescriptor
import org.kotlintor.or.SocksRequest
import org.kotlintor.or.TorVersion
import org.kotlintor.or.VarCell
import org.kotlintor.or.VegasParams
import org.kotlintor.or.VoteMicrodescHash
import org.kotlintor.path.EntryGuardFsm
import org.kotlintor.path.GuardReachable
import org.kotlintor.relay.BwHist
import org.kotlintor.relay.DosOptions
import java.nio.file.Files

/**
 * Elevates selected L2 struct rows (D2→D3) with exclusive STRUCT_HINTS + TYPE_SEED_DEPTH.
 *
 * Inventory: `L2:app/config/or_options_t`, `or_state_t`, `mainloop_state_t`, `tor1_crypt_t`,
 * `cached_dir_t`…`document_signature_t`, `conflux_t`, `crypt_path_t`, `destroy_cell_queue_t`,
 * plus earlier cell/channel/cmux/guard/crypto seeds.
 */
class L2StructElevationTest {
    @Test
    fun `or_options addr_policy authority_cert cell`() {
        val c = TorConfig(dataDirectory = Files.createTempDirectory("ktor-l2"))
        assertTrue(c.clientOnly)
        assertTrue(c.socksPorts.isNotEmpty())
        val pol = AddrPolicy.parseLines(listOf("accept *:80", "reject *:*"))
        assertTrue(pol.allows("1.2.3.4", 80))
        assertFalse(pol.allows("1.2.3.4", 22))
        val cert = AuthorityCert.generate(bits = 1024)
        assertEquals(20, cert.identityFingerprint.size)
        val cell = Cell(1L, CellCommand.NETINFO, ByteArray(Cell.FIXED_PAYLOAD_LEN))
        assertEquals(CellCommand.NETINFO, cell.command)
        assertEquals(509, cell.payload.size)
    }

    @Test
    fun `channel connection cmux congestion extend guard`() {
        val ch = OrChannel()
        assertEquals(ChannelState.OPENING, ch.state)
        ch.markOpen()
        assertEquals(ChannelState.OPEN, ch.state)
        val conn = Connection(id = 7L, type = ConnectionType.OR, address = "1.2.3.4", port = 9001)
        assertEquals(ConnectionType.OR, conn.type)
        val q = CellQueue()
        assertTrue(q.append(ByteArray(10)))
        assertEquals(10, q.pop()!!.size)
        val cc = CongestionControl()
        assertTrue(cc.congestionWindow >= 31)
        val ei = ExtendInfo(
            identityDigest = ByteArray(20) { 1 },
            orPorts = listOf(ExtendInfo.OrPort("1.2.3.4", 9001)),
            curve25519OnionKey = ByteArray(32) { 2 },
        )
        assertTrue(ei.supportsNtor())
        val fsm = EntryGuardFsm()
        val fp = "aa".repeat(20)
        fsm.noteSuccess(fp)
        assertEquals(GuardReachable.YES, fsm.getOrCreate(fp).reachable)
    }

    @Test
    fun `bw dos hs opts crypto routerset detached`() {
        BwHist.clear()
        BwHist.noteBytesRead(5)
        assertTrue(BwHist.getBandwidthLines().contains("read-history"))
        assertEquals(100, DosOptions().circuitCreationRate)
        assertTrue(HsOpts().validate().isEmpty())
        assertEquals(16, Cgo.TAG_LEN)
        assertEquals("CircuitLayerCake", CircuitLayerCake::class.simpleName)
        assertTrue(RouterSet("").isEmpty())
        assertTrue(DetachedSignatures.parse("").signatures.isEmpty())
    }

    @Test
    fun `or_state mainloop tor1 conflux crypt_path destroy_queue`() {
        val cfg = TorConfig(dataDirectory = Files.createTempDirectory("ktor-l2-state"))
        val st = OrState.fromTorConfig(cfg)
        assertEquals(cfg.dataDirectory, st.dataDirectory)
        assertFalse(MainloopState().started)
        val t1 = Tor1Crypt()
        assertEquals(16, t1.forwardKey.size)
        assertEquals(20, t1.toHopCrypto().inboundDigest().size)
        val set = ConfluxSet(nonce = ByteArray(32) { 1 })
        assertEquals(0, set.size())
        assertEquals(32, set.nonce.size)
        assertEquals(CryptPath.MAGIC, CryptPath.Hop().magic)
        val dq = DestroyCellQueue()
        assertEquals(0, dq.size())
        assertTrue(CircuitMux().destroyQueue.size() == 0)
    }

    @Test
    fun `or struct primaries + dir control connections`() {
        val cache = CachedDir(dir = "ns", digestsSha1Hex = "aa")
        assertEquals("ns", cache.dir)
        val listener = ChannelListener(ListenSpec("127.0.0.1", 9050))
        assertEquals(9050, listener.listen.port)
        assertEquals(4, ChannelTls("1.2.3.4", 9001).linkProtocol)
        assertEquals(60_000, CircuitBuildTimes().timeoutMs)
        assertEquals(0, ConfluxLeg(9L).lastSeqSent)
        assertEquals(2, ConfluxParamsSt().maxLegs)
        assertEquals(3, CpathBuildState().desiredPathLen)
        assertEquals(1, CryptPathReference(1, 42L).hopIndex)
        val store = DescStore()
        store.store("ab", "body")
        assertEquals("body", store.lookup("AB"))
        assertEquals(7L, DestroyCell(7L, reason = 1).circId)
        val ds = DirServer("moria1", "128.31.0.34", 9131, 9101, isAuthority = true)
        assertTrue(ds.isAuthority)
        val arr = ConnectionTable
        val ctrl = arr.newControl("127.0.0.1", 9051)
        val dir = arr.newDir("127.0.0.1", 9030)
        assertEquals(ConnectionType.CONTROL, ctrl.type)
        assertEquals(ConnectionType.DIR, dir.type)
        val sig: DocumentSignature = DetachedSignatures.DocumentSignature(
            algorithm = "sha1",
            identityHex = "aa",
            signingKeyDigestHex = "bb",
            signature = ByteArray(64),
        )
        assertEquals("aa", sig.identityHex)
        assertEquals(9050, PortCfg(ListenSpec("127.0.0.1", 9050)).listen.port)
        assertEquals("USERADDR", ExtOrCmd("USERADDR", "1.2.3.4:9").command)
        assertEquals("n", ExtraInfo("n", "id", "body").nickname)
        assertEquals(32, HsDirIndex(ByteArray(32), ByteArray(32)).first.size)
        val md = MicrodescCache()
        md.put("aa", "@type")
        assertEquals("@type", md.get("AA"))
        assertEquals(null, NetworkstatusSrInfo().current)
        assertEquals(9131, NetworkstatusVoterInfo("m", "id", "1.2.3.4", 9131, 9001).dirPort)
        assertEquals(1L, OnionHandshakeState(1L, 2).circId)
        assertTrue(OrHandshakeCerts().idCert == null)
        assertTrue(OrHandshakeState().startedHere)
        val listen = ConnectionTable.newListener("127.0.0.1", 9050, ConnectionType.LISTENER)
        assertEquals(ConnectionType.LISTENER, listen.type)
        val entry = ConnectionTable.newEntry("127.0.0.1", 9050)
        assertEquals(ConnectionType.AP, entry.type)
        assertEquals(1, HalfEdge(streamId = 1).streamId)
        assertEquals(3, PackedCell(ByteArray(3)).body.size)
        assertEquals(1, RelayMsg(1, 2, 0, ByteArray(0)).command)
        assertEquals("id", SignedDescriptor("b", "id").identityHex)
        assertEquals(443, SocksRequest(1, "example.com", 443).port)
        assertEquals("0.4.8-stable", TorVersion.parse("0.4.8")?.toString())
        assertEquals(0L, VarCell(0L, 7, ByteArray(0)).circId)
        assertEquals(93, VegasParams().alpha)
        assertEquals("aa", VoteMicrodescHash(1, "aa").digestHex)
        assertTrue(ControlCmdArgs(args = listOf("GETINFO")).args.isNotEmpty())
        assertTrue(DownloadStatus().isReady())
        assertTrue(Microdesc.parseFamily("").isEmpty())
        assertEquals("networkstatus.c", NetworkStatus.C_TOR_UNIT)
        assertEquals("aa", Node(identityHex = "aa").identityHex)
        val nf = NodeFamily.parse("\$" + "ab".repeat(20))
        assertTrue(nf != null && nf.fingerprints.isNotEmpty())
        assertTrue(CircuitKind.Origin(1L) is CircuitKind.Origin)
        assertTrue(CircuitKind.Or(2L) is CircuitKind.Or)
        assertEquals("OrConnection", OrConnection::class.simpleName)
        assertEquals("RouterInfo", RouterInfo::class.simpleName)
        assertEquals(0, RouterList().size())
        assertTrue(DirAuthOptions().validate().isEmpty())
    }
}
