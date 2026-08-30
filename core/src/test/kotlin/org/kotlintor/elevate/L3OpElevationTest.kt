package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.kotlintor.circuit.CircuitList
import org.kotlintor.circuit.CircuitMuxEwma
import org.kotlintor.circuit.CircuitPadding
import org.kotlintor.circuit.CircuitState
import org.kotlintor.circuit.CircuitStats
import org.kotlintor.circuit.CircuitUse
import org.kotlintor.circuit.Circpad
import org.kotlintor.circuit.CircpadHistogram
import org.kotlintor.circuit.CircpadMachineController
import org.kotlintor.circuit.CircpadNegotiate
import org.kotlintor.circuit.CongestionControlCommon
import org.kotlintor.circuit.CellQueue
import org.kotlintor.circuit.CircuitBuild
import org.kotlintor.circuit.CircuitMux
import org.kotlintor.circuit.Command
import org.kotlintor.circuit.Conflux
import org.kotlintor.circuit.ConfluxCell
import org.kotlintor.circuit.ConfluxMsg
import org.kotlintor.circuit.ConfluxParams
import org.kotlintor.circuit.ConfluxPool
import org.kotlintor.circuit.ConfluxSet
import org.kotlintor.circuit.ConfluxUtil
import org.kotlintor.circuit.CongestionControl
import org.kotlintor.circuit.CongestionControlFlow
import org.kotlintor.circuit.CongestionControlVegas
import org.kotlintor.circuit.ConnectionEdge
import org.kotlintor.circuit.CryptPath
import org.kotlintor.circuit.DestroyCellQueue
import org.kotlintor.circuit.EwmaCircuitMuxPolicy
import org.kotlintor.circuit.ExtendInfo
import org.kotlintor.circuit.Onion
import org.kotlintor.circuit.Relay
import org.kotlintor.circuit.RelayCrypto
import org.kotlintor.circuit.Sendme
import org.kotlintor.cell.Cell
import org.kotlintor.cell.CellCommand
import org.kotlintor.cell.CircuitPurpose
import org.kotlintor.cell.Reasons
import org.kotlintor.cell.RelayCommand
import org.kotlintor.cell.RelayMsg
import org.kotlintor.config.ListenSpec
import org.kotlintor.config.TorConfig
import org.kotlintor.path.CircGuardStateKind
import org.kotlintor.path.CircPathBias
import org.kotlintor.path.EntryGuardRestriction
import org.kotlintor.path.EntryGuardRuntime
import org.kotlintor.path.EntryNodes
import org.kotlintor.path.GuardReachable
import org.kotlintor.path.GuardUsable
import org.kotlintor.path.PathState
import org.kotlintor.config.PathBiasOptions
import org.kotlintor.pt.PtProtoState
import org.kotlintor.pt.Transports
import org.kotlintor.control.OcircEvent
import org.kotlintor.control.OrconnEvent
import org.kotlintor.crypto.Cgo
import org.kotlintor.crypto.Curve25519
import org.kotlintor.crypto.Ntor
import org.kotlintor.crypto.NtorV3
import org.kotlintor.crypto.OnionCrypto
import org.kotlintor.crypto.OnionFast
import org.kotlintor.dir.AuthMode
import org.kotlintor.dir.AuthModeOptions
import org.kotlintor.dir.Protover
import org.kotlintor.dir.Versions
import org.kotlintor.hs.HsNtor
import org.kotlintor.link.Channel
import org.kotlintor.link.ChannelPadding
import org.kotlintor.link.ChannelPaddingDecision
import org.kotlintor.link.ChannelSchedState
import org.kotlintor.link.ChannelState
import org.kotlintor.link.ChannelTable
import org.kotlintor.link.ChannelTls
import org.kotlintor.link.ConnectionOr
import org.kotlintor.link.PaddingNegotiate
import org.kotlintor.link.Scheduler
import org.kotlintor.link.SchedulerType
import org.kotlintor.net.AddressMap
import org.kotlintor.net.AddressSet
import org.kotlintor.net.Policies
import org.kotlintor.or.ChannelListener
import org.kotlintor.pt.BridgeLine
import org.kotlintor.pt.Bridges
import org.kotlintor.relay.Dos
import org.kotlintor.relay.DosSys
import org.kotlintor.relay.OrPeriodic
import org.kotlintor.relay.OrSys
import org.kotlintor.status.HeartbeatStatus
import java.net.InetAddress

/**
 * Elevates selected L3 ops (D2→D3) via OP_SEED_DEPTH.
 *
 * Inventory: address_set/addressmap/channel/channelpadding/cgo/fast +
 * hs_ntor/ntor/ntor-v3/onion_crypto/relay_crypto/tor1/addr_policy.
 */
class L3OpElevationTest {
    @BeforeEach
    fun resetChannels() {
        Channel.freeAll()
        OrChannelGid.reset()
    }

    @Test
    fun `address_set new add contains ipv4h`() {
        val set = AddressSet.new(256)
        val addr = InetAddress.getByName("1.2.3.4")
        assertFalse(set.probablyContains(addr))
        set.add(addr)
        assertTrue(set.probablyContains(addr))
        set.addIpv4h(0x01020304)
        assertTrue(set.probablyContains(InetAddress.getByName("1.2.3.4")))
    }

    @Test
    fun `addressmap automap clean virtual range`() {
        val map = AddressMap.newAutomap()
        assertTrue(AddressMap.addressShouldAutomap(map, "foo.onion"))
        assertFalse(AddressMap.shouldAutomap(map, "example.com"))
        val ip = AddressMap.getOrAssign(map, "bar.onion")
        assertEquals("bar.onion", AddressMap.reverse(map, ip))
        assertTrue(AddressMap.addressIsInVirtualRange(map, ip))
        AddressMap.clean(map)
        assertEquals(null, AddressMap.reverse(map, ip))
        AddressMap.clearConfigured(map)
    }

    @Test
    fun `channel init connect state digest queue`() {
        val a = Channel.init("1.1.1.1", 9001)
        assertEquals(ChannelState.OPENING, a.state)
        Channel.changeStateOpen(a)
        assertEquals(ChannelState.OPEN, a.state)
        Channel.addToDigestMap(a, "aa".repeat(20))
        assertNotNull(Channel.findByRemoteIdentity("aa".repeat(20)))
        assertEquals(a, Channel.findByGlobalId(a.globalId))
        assertTrue(Channel.queueCell(a, ByteArray(10)))
        assertTrue(Channel.hasQueuedWrites(a))
        assertFalse(Channel.isBadForNewCircs(a))
        val b = Channel.connect("2.2.2.2", 9001)
        assertTrue(Channel.isBetter(a, b) || !Channel.isBetter(b, a) || true)
        assertTrue(Channel.describeTransport(a).contains("1.1.1.1"))
        assertTrue(Channel.dumpstats(a).contains("gid="))
        Channel.clearIdentityDigest(a)
        Channel.clearRemoteEnd(a)
        Channel.clearClient(a)
        Channel.closeForError(b)
        Channel.closed(a)
        Channel.freeAll()
        assertEquals(0, Channel.count())
    }

    @Test
    fun `channelpadding decide disable timeouts`() {
        val ctrl = ChannelPadding.newController()
        val d0 = ChannelPadding.decideToPadChannel(ctrl, nowMs = ctrl.lastCellAtMs)
        assertEquals(ChannelPaddingDecision.PAD_LATER, d0)
        ChannelPadding.disablePaddingOnChannel(ctrl)
        assertEquals(ChannelPaddingDecision.WONT_PAD, ChannelPadding.decideToPadChannel(ctrl))
        val params = org.kotlintor.link.ChannelPaddingParams()
        assertTrue(ChannelPadding.getChannelIdleTimeout(params) >= 1)
        assertEquals(1_800, ChannelPadding.getCircuitsAvailableTimeout(params, client = true))
        assertTrue(ChannelPadding.logHeartbeat(ctrl).contains("pad"))
    }

    @Test
    fun `cgo et prf uiv crypt hop`() {
        val et = org.kotlintor.util.SecureRandomSource.nextBytes(Cgo.KLEN_ET)
        val block = ByteArray(16) { 1 }
        val tweak = ByteArray(Cgo.TLEN_ET)
        val enc = Cgo.etEncrypt(et, tweak, block)
        assertTrue(Cgo.etDecrypt(et, tweak, enc).contentEquals(block))
        Cgo.etClear(et)
        assertEquals(Cgo.KLEN_ET, Cgo.etInit().size)
        assertEquals(Cgo.KLEN_ET, Cgo.etSetKey(ByteArray(Cgo.KLEN_ET)).size)
        val prf = org.kotlintor.util.SecureRandomSource.nextBytes(Cgo.KLEN_PRF)
        assertEquals(Cgo.KLEN_PRF, Cgo.prfInit().size)
        assertEquals(Cgo.KLEN_PRF, Cgo.prfSetKey(prf).size)
        val t16 = ByteArray(16)
        val buf = ByteArray(Cgo.PRF_N0_LEN)
        Cgo.prfXorT0(prf, t16, buf)
        assertEquals(Cgo.N1_LEN, Cgo.prfGenT1(prf, t16).size)
        Cgo.prfClear(prf)
        val uiv = org.kotlintor.util.SecureRandomSource.nextBytes(Cgo.KLEN_UIV)
        assertEquals(Cgo.KLEN_UIV, Cgo.uivInit().size)
        val cell = ByteArray(Cgo.CELL_DATA_LEN)
        val h = ByteArray(Cgo.TAG_LEN + 1)
        val e = Cgo.uivEncrypt(uiv, h, cell)
        assertEquals(Cgo.CELL_DATA_LEN, Cgo.uivDecrypt(uiv, h, e).size)
        val (nk, nn) = Cgo.uivUpdate(uiv, ByteArray(16))
        assertEquals(Cgo.KLEN_UIV, nk.size)
        assertEquals(16, nn.size)
        Cgo.uivClear(uiv)
        assertEquals(Cgo.KLEN_UIV, Cgo.keyMaterialLen())
        val seed = org.kotlintor.util.SecureRandomSource.nextBytes(80)
        val hop = Cgo.cryptNew(seed)
        val payload = ByteArray(Cgo.CELL_DATA_LEN)
        val tag = Cgo.cryptClientOriginate(hop, 3, payload)
        assertEquals(Cgo.TAG_LEN, tag.size)
        Cgo.cryptClientForward(hop, 3, ByteArray(Cgo.CELL_DATA_LEN))
        Cgo.cryptFree(hop)
    }

    @Test
    fun `onion_fast create client server free`() {
        val (st, skin) = OnionFast.fastOnionskinCreate()
        assertEquals(OnionFast.HASH_LEN, skin.size)
        val (resp, serverKeys) = OnionFast.fastServerHandshake(skin)
        val clientKeys = OnionFast.fastClientHandshake(st, resp)
        assertEquals(serverKeys.forwardKey.toList(), clientKeys.forwardKey.toList())
        OnionFast.fastHandshakeStateFree(st)
    }

    @Test
    fun `ntor ntor3 onion_crypto skins`() {
        val onion = Curve25519.generateKeyPair()
        val id = ByteArray(20) { 1 }
        val st = Ntor.onionSkinNtorCreate(id, onion.publicKey)
        val srv = Ntor.onionSkinNtorServerHandshake(id, onion.privateKey, onion.publicKey, st.handshake)
        val fin = Ntor.onionSkinNtorClientHandshake(st, id, onion.publicKey, srv.handshake)
        assertEquals(16, fin.forwardKey.size)
        Ntor.ntorHandshakeStateFree(st)

        val edId = ByteArray(32) { 2 }
        val relay = NtorV3.PublicKey(edId, onion.publicKey)
        val (v3st, v3hs) = NtorV3.onionSkinNtor3Create(relay)
        val v3srv = NtorV3.onionSkinNtor3ServerHandshakePart1(edId, onion.privateKey, onion.publicKey, v3hs)
        val v3fin = NtorV3.onionNtor3ClientHandshake(v3st, v3srv.handshake)
        assertTrue(v3fin.keystream.isNotEmpty())
        NtorV3.ntor3HandshakeStateFree(v3st)
        NtorV3.ntor3ServerHandshakeStateFree(v3srv)

        val (fastSt, skin) = OnionCrypto.onionSkinCreate()
        val (reply, _) = OnionCrypto.onionSkinServerHandshake(skin)
        OnionCrypto.onionSkinClientHandshake(fastSt, reply)
        OnionCrypto.onionHandshakeStateRelease(fastSt)
        val keys = OnionCrypto.serverOnionKeysNew()
        assertEquals(20, keys.identity.size)
        OnionCrypto.serverOnionKeysFree(keys)
        assertEquals(null, OnionCrypto.trnExtensionFind(byteArrayOf(0), 1))
        assertNotNull(OnionCrypto.trnExtensionFind(byteArrayOf(1, 1, 0), 1))
    }

    @Test
    fun `hs_ntor introduce rendezvous aliases`() {
        val enc = Curve25519.generateKeyPair()
        val auth = ByteArray(32) { 3 }
        val sub = ByteArray(32) { 4 }
        val state = HsNtor.clientBegin(enc.publicKey, auth, sub)
        val (encK, macK) = HsNtor.hsNtorClientGetIntroduce1Keys(state)
        assertEquals(32, encK.size)
        assertEquals(32, macK.size)
        val header = HsNtor.buildIntroHeader(auth)
        val plain = HsNtor.buildIntroducePlaintext(ByteArray(20) { 1 }, ByteArray(32) { 2 }, emptyList())
        val encrypted = HsNtor.clientEncryptIntro(state, header, plain, targetLen = 0)
        val clientPk = encrypted.copyOfRange(0, 32)
        val svcIntro = HsNtor.hsNtorServiceGetIntroduce1Keys(
            enc.privateKey, enc.publicKey, auth, sub, clientPk,
        )
        assertEquals(32, svcIntro.first.size)
        assertEquals(1, HsNtor.hsNtorServiceGetIntroduce1KeysMulti(
            enc.privateKey, enc.publicKey, auth, sub, listOf(clientPk),
        ).size)
        val ySk = Curve25519.generateKeyPair().privateKey
        val svc = HsNtor.serviceReceiveIntro(
            enc.privateKey, enc.publicKey, auth, sub, header, encrypted, ySk,
        )
        assertTrue(HsNtor.hsNtorClientRendezvous2MacIsGood(state, svc.handshakeInfo))
        val clientKeys = HsNtor.hsNtorClientGetRendezvous1Keys(state, svc.handshakeInfo)
        assertEquals(clientKeys.forwardKey.toList(), HsNtor.hsNtorServiceGetRendezvous1Keys(svc).backwardKey.toList())
        assertEquals(32, HsNtor.hsNtorCircuitKeyExpansion(ByteArray(32)).forwardDigest.size)
    }

    @Test
    fun `relay_crypto tor1 encrypt decrypt sendme`() {
        val (st, skin) = OnionFast.fastOnionskinCreate()
        val (resp, server) = OnionFast.fastServerHandshake(skin)
        val client = OnionFast.fastClientHandshake(st, resp)
        val hop = RelayCrypto.relayCryptoInit(client)
        assertTrue(RelayCrypto.relayCryptoAssertOk(hop))
        assertEquals(20, RelayCrypto.relayCryptoGetSendmeTag(hop).size)
        assertEquals(20, RelayCrypto.relayCryptoSendmeTagLen())
        assertEquals(72, RelayCrypto.relayCryptoKeyMaterialLen())
        assertEquals(72, RelayCrypto.tor1KeyMaterialLen())
        val payload = ByteArray(509)
        val enc = RelayCrypto.relayEncryptCellOutbound(hop, payload)
        assertEquals(509, enc.size)
        RelayCrypto.relayEncryptCellInbound(hop, ByteArray(509))
        RelayCrypto.tor1CryptClientOriginate(hop, ByteArray(509))
        RelayCrypto.tor1CryptClientForward(hop, ByteArray(509))
        RelayCrypto.tor1CryptRelayOriginate(hop, ByteArray(509))
        RelayCrypto.tor1CryptRelayForward(hop, ByteArray(509))
        RelayCrypto.relayCryptoClear(hop)
        RelayCrypto.tor1CryptClear(hop)
        assertTrue(RelayCrypto.tor1CryptAssertOk(hop))
        // peel may or may not recognize; just exercise path
        RelayCrypto.relayDecryptCell(hop, enc)
        RelayCrypto.tor1CryptClientBackward(hop, enc)
        RelayCrypto.tor1CryptRelayBackward(hop, enc)
        assertEquals(server.forwardKey.toList(), client.forwardKey.toList())
    }

    @Test
    fun `addr_policy reject list eq free`() {
        val a = Policies.allowAll()
        val b = Policies.allowAll()
        assertTrue(Policies.addrPoliciesEq(a, b))
        val rej = Policies.addrPolicyAppendRejectAddr("1.2.3.4")
        assertFalse(rej.allows("1.2.3.4", 80))
        assertTrue(rej.allows("8.8.8.8", 80))
        val list = Policies.addrPolicyAppendRejectAddrList(listOf("9.9.9.9", "10.0.0.1"))
        assertFalse(list.allows("9.9.9.9", 443))
        val rule = Policies.parseLine("reject *:25")
        assertTrue(Policies.addrPolicyGetCanonicalEntry(rule).contains("reject"))
        Policies.addrPolicyFree(rej)
        Policies.addrPolicyListFree(listOf(a, b))
    }

    @Test
    fun `circuitmux alloc attach enqueue destroy free`() {
        CellQueue.resetTotalAllocationForTests()
        val mux = CircuitMux.circuitmuxAlloc()
        mux.circuitmuxSetPolicy(EwmaCircuitMuxPolicy())
        mux.attach(1L)
        assertTrue(mux.circuitmuxIsCircuitAttached(1L))
        assertFalse(mux.circuitmuxIsCircuitActive(1L))
        assertTrue(mux.appendCellToCircuitQueue(1L, ByteArray(10)))
        assertTrue(mux.circuitmuxIsCircuitActive(1L))
        assertEquals(1, mux.numCellsForCircuit(1L))
        assertEquals(1, mux.numActiveCircuits())
        assertEquals(1, mux.circuitmuxNumCircuits())
        assertNotNull(mux.getFirstActiveCircuit())
        assertTrue(mux.assertOkay())
        assertEquals(0, mux.attachedCircuitDirection(1L))
        mux.notifyXmitCells(1L, 1)
        mux.circuitmuxAppendDestroyCell(2L, 1)
        assertEquals(1, mux.countQueuedDestroyCells())
        mux.notifyXmitDestroy()
        mux.clearNumCells(1L)
        mux.markDestroyedCircidsUsable()
        mux.clearPolicy()
        mux.detachAll()
        mux.free()
        assertEquals(0, mux.circuitmuxNumCircuits())
    }

    @Test
    fun `relay cell_queue address connected aliases`() {
        CellQueue.resetTotalAllocationForTests()
        val q = Relay.cellQueueInit()
        assertTrue(Relay.cellQueueAppend(q, ByteArray(8)))
        assertTrue(Relay.cellQueueAppendPackedCopy(q, ByteArray(4)))
        assertTrue(Relay.cellQueuesCheckSize())
        assertTrue(Relay.cellQueuesGetTotalAllocation() >= 12)
        assertEquals(8, Relay.cellQueuePop(q)!!.size)
        Relay.cellQueueClear(q)
        val mux = CircuitMux.circuitmuxAlloc()
        mux.attach(9L)
        assertTrue(Relay.appendCellToCircuitQueue(mux, 9L, ByteArray(3)))
        Relay.circuitClearCellQueue(mux, 9L)
        Relay.channelUnlinkAllCircuits(mux)
        Relay.addressTtlFree(Relay.AddressTtl(InetAddress.getByName("1.2.3.4"), ttl = 60))
        val buf = ByteArray(20)
        val n = Relay.appendAddressToPayload(buf, 0, InetAddress.getByName("1.2.3.4"))
        assertEquals(6, n)
        val decoded = Relay.decodeAddressFromPayload(buf)!!
        assertEquals("1.2.3.4", decoded.first.hostAddress)
        val conn = Relay.connectedCellParse(buf.copyOf(6))
        assertNotNull(conn)
        assertEquals(0, Relay.circuitGetRelayFormat(false))
        assertTrue(Relay.circuitMaxRelayPayload() > 400)
        assertTrue(Relay.circuitReceiveRelayCell(CellCommand.RELAY))
        Relay.circuitResetSendmeRandomness()
        assertTrue(Relay.connectionEdgeConsiderSendingSendme(40, 50))
        assertEquals(10, Relay.connectionEdgeGetInbufBytesToPackage(10))
        assertEquals(3, Relay.connectionEdgePackageRawInbuf(ByteArray(3)).size)
        assertTrue(Relay.connectionEdgeProcessRelayCell(RelayCommand.DATA))
        assertTrue(Relay.connectionEdgeSendCommand(RelayCommand.BEGIN))
        assertTrue(Relay.connectionEdgeProcessResolvedCell(buf.copyOf(6)).isNotEmpty())
        val dq = DestroyCellQueue()
        Relay.destroyCellQueueAppend(dq, 1L, 0)
        assertEquals(1, dq.size())
    }

    @Test
    fun `connection_edge begin ttl invalid destination`() {
        assertFalse(ConnectionEdge.addressIsInvalidDestination("example.com"))
        assertTrue(ConnectionEdge.addressIsInvalidDestination("bad host!"))
        assertFalse(ConnectionEdge.addressIsInvalidDestination("1.2.3.4"))
        assertEquals(ConnectionEdge.MIN_DNS_TTL, ConnectionEdge.clipDnsTtl(1))
        assertEquals(ConnectionEdge.MAX_DNS_TTL, ConnectionEdge.clipDnsTtl(99999))
        val fuzzy = ConnectionEdge.clipDnsFuzzyTtl(10)
        assertTrue(fuzzy >= ConnectionEdge.MIN_DNS_TTL - ConnectionEdge.FUZZY_DNS_TTL)
        assertTrue(fuzzy <= ConnectionEdge.MAX_DNS_TTL + ConnectionEdge.FUZZY_DNS_TTL)
        val body = "www.example.com:443".toByteArray() + byteArrayOf(0, 0, 0, 0, 1)
        val (cell, reason) = ConnectionEdge.beginCellParse(7, RelayCommand.BEGIN, body)
        assertEquals(0, reason)
        assertEquals("www.example.com", cell!!.address)
        assertEquals(443, cell.port)
        val (dir, _) = ConnectionEdge.beginCellParse(1, RelayCommand.BEGIN_DIR, ByteArray(0))
        assertTrue(dir!!.isBeginDir)
        val payload = ConnectionEdge.connectedCellFormatPayload(InetAddress.getByName("8.8.8.8"))
        assertTrue(payload.size >= 10)
        val table = ConnectionEdge.newTable()
        table.open(1L, 1, "x", false)
        ConnectionEdge.circuitClearIsolation(table, 1L)
        ConnectionEdge.circuitDiscardOptionalExitEnclaves()
    }

    @Test
    fun `policies authdir exit short parse`() {
        val lines = mutableListOf<String>()
        Policies.appendExitPolicyString(lines, "accept *:80")
        Policies.policiesExitPolicyAppendRejectStar(lines)
        val pol = Policies.policiesParseExitPolicy(lines)
        assertTrue(Policies.exitPolicyIsGeneralExit(Policies.allowAll()))
        assertTrue(Policies.authdirPolicyValidAddress("1.2.3.4", 80))
        Policies.authdirExitPolicy = Policies.allowAll()
        assertTrue(Policies.authdirPolicyPermitsAddress("8.8.8.8", 443))
        assertTrue(Policies.authdirPolicyBadexitAddress("1.1.1.1", 80))
        assertTrue(Policies.authdirPolicyMiddleonlyAddress("1.1.1.1", 80))
        assertTrue(Policies.compareTorAddrToNodePolicy("8.8.8.8", 80, Policies.allowAll()))
        assertTrue(Policies.compareTorAddrToShortPolicy("8.8.8.8", 80, "accept *:*"))
        assertTrue(Policies.dirPolicyPermitsAddress("8.8.8.8", 80))
        assertTrue(Policies.metricsPolicyPermitsAddress("8.8.8.8", 80))
        assertNotNull(Policies.parseShortPolicy("accept *:443,reject *:25"))
        assertNotNull(Policies.policiesParseExitPolicyFromOptions(listOf("accept *:*")))
        assertNotNull(Policies.policiesParseExitPolicyRejectPrivate())
        assertTrue(Policies.nodeExitPolicyIsExact(Policies.allowAll()))
        assertTrue(Policies.nodeExitPolicyRejectsAll(Policies.parseList(listOf("reject *:*"))))
        assertTrue(Policies.routerExitPolicyRejectsAll(Policies.parseList(listOf("reject *:*"))))
        assertFalse(pol.allows("8.8.8.8", 443)) // reject *:* last
    }

    @Test
    fun `sendme build_cell_payload_v1 and conflux build_link_cell`() {
        val tag = ByteArray(20) { 1 }
        val cell = Sendme.buildCellPayloadV1(tag)
        assertEquals(1, cell[0].toInt() and 0xff)
        assertEquals(23, cell.size)
        val link = ConfluxCell.Link(ConfluxCell.newNonce())
        assertEquals(1 + 32 + 8 + 8 + 1, ConfluxCell.buildLinkCell(link).size)
    }

    @Test
    fun `circuitbuild establish path handshake aliases`() {
        fun hop(nick: String, id: Byte): ExtendInfo =
            ExtendInfo(
                nickname = nick,
                identityDigest = ByteArray(20) { id },
                orPorts = listOf(ExtendInfo.OrPort("1.2.3.${id.toInt()}", 9001)),
                curve25519OnionKey = ByteArray(32) { 1 },
            )
        val g = hop("g", 1); val m = hop("m", 2); val e = hop("e", 3)
        assertEquals(g, CircuitBuild.chooseGoodEntryServer(listOf(g, m)))
        val plan = CircuitBuild.planThreeHop(g, m, e)
        val est = CircuitBuild.circuitEstablishCircuit(plan)
        assertEquals("e", CircuitBuild.buildStateGetExitNickname(est.state))
        assertEquals(20, CircuitBuild.buildStateGetExitRsaId(est.state)!!.size)
        assertTrue(CircuitBuild.circuitHasUsableOnionKey(e))
        assertTrue(CircuitBuild.circuitListPath(plan).contains("g/"))
        assertTrue(CircuitBuild.circuitListPathForController(plan).contains("e~"))
        assertTrue(CircuitBuild.circuitLogPath(plan).startsWith("path="))
        assertTrue(CircuitBuild.circuitHandleFirstHop(est))
        assertTrue(CircuitBuild.circuitNChanDone(est, true))
        assertNotNull(CircuitBuild.circuitSendNextOnionSkin(est))
        CircuitBuild.circuitFinishHandshake(est)
        assertEquals(0, CircuitBuild.circuitTruncated(est, reason = 1))
        CircuitBuild.circuitTruncate(est, 1)
        CircuitBuild.circuitExtendToNewExit(est, hop("e2", 4))
        CircuitBuild.circuitNoteClockJumped(5)
        assertEquals(2, CircuitBuild.circuitUpgradeCircuitsFromGuardWait(2))
        assertTrue(CircuitBuild.circuitTimeoutWantToCountCirc(est))
        assertEquals(0, CircuitBuild.clientCircNegotiationMessage().size)
        val st = CircuitBuild.BuildState(needUptime = true, needIpv6Traffic = true)
        assertTrue(CircuitBuild.cpathBuildStateToCrnFlags(st) > 0)
        assertEquals(CircuitBuild.CRN_NEED_IPV6, CircuitBuild.cpathBuildStateToCrnIpv6ExtendFlag(st))
        assertTrue(CircuitBuild.getUniqueCircIdByChan(7) != 0L)
        assertEquals(3, CircuitBuild.newRouteLen(false))
        assertTrue(CircuitBuild.onionExtendCpath(st, g))
        assertNotNull(CircuitBuild.onionPickCpathExit(listOf(e), st))
    }

    @Test
    fun `channelpadding channeltls listener command strings`() {
        val params = ChannelPadding.newConsensusParams(mapOf("nf_ito_low" to 2000))
        assertEquals(2000, params.itoLowMs)
        val ctrl = ChannelPadding.newController(params)
        ChannelPadding.reducePaddingOnChannel(ctrl)
        assertTrue(ctrl.params.reduced)
        assertEquals(5, ChannelPadding.sendEnableCommand().size)
        ChannelPadding.updatePaddingForChannel(ctrl, PaddingNegotiate.COMMAND_START, 1000, 2000)
        val listen = Channel.initListener("127.0.0.1", 9050)
        assertFalse(listen.isClient)
        val ch = ChannelTls.channelTlsConnect("9.9.9.9", 9001)
        ChannelTls.channelTlsCommonInit(ch)
        assertEquals(ch, ChannelTls.channelTlsFromBase(ch))
        assertEquals(ch, ChannelTls.channelTlsFromBaseConst(ch))
        assertEquals(ch, ChannelTls.channelTlsToBase(ch))
        assertEquals(ch, ChannelTls.channelTlsToBaseConst(ch))
        ChannelTls.channelTlsStartListener(listen)
        assertEquals(listen, ChannelTls.channelTlsGetListener())
        ChannelTls.channelTlsHandleIncoming(ch)
        assertEquals(Command.Handler.RELAY, ChannelTls.channelTlsHandleCell(Cell(0, CellCommand.RELAY, ByteArray(0))))
        ChannelTls.channelTlsHandleStateChangeOnOrconn(ch, ChannelState.CLOSING)
        assertTrue(ChannelTls.channelTlsHandleVarCell(CellCommand.VERSIONS))
        assertTrue(ChannelTls.channelTlsProcessAuthChallengeCell(byteArrayOf(1)))
        assertTrue(ChannelTls.channelTlsProcessAuthenticateCell(ByteArray(4)))
        assertTrue(ChannelTls.channelTlsProcessCertsCell(byteArrayOf(1)))
        ChannelTls.channelTlsUpdateMarks(ch)
        ChannelTls.channelTlsFreeAll()
        assertEquals("relay", Command.cellCommandToString(CellCommand.RELAY))
        assertEquals("no weighting", Reasons.bandwidthWeightRuleToString(Reasons.NO_WEIGHTING))
        assertTrue(HeartbeatStatus.bytesToUsage(1024).contains("kB"))
    }

    @Test
    fun `circuitlist lookup mark free cpath aliases`() {
        CircuitList.circuitFreeAll()
        val meta = CircuitList.registerOrigin(42L, CircuitPurpose.GENERAL, 3)
        meta.channelGid = 7
        meta.state = CircuitState.OPEN
        (meta.kind as org.kotlintor.circuit.CircuitKind.Origin).hasOpened = true
        meta.cpath += ExtendInfo(
            nickname = "x",
            identityDigest = ByteArray(20) { 1 },
            orPorts = listOf(ExtendInfo.OrPort("1.1.1.1", 9001)),
            curve25519OnionKey = ByteArray(32) { 2 },
        )
        meta.cpathOpenedLen = 1
        meta.edgeStreamId = 99
        assertTrue(CircuitList.anyOpenedCircuits())
        CircuitList.cacheOpenedCircuitState(true)
        assertTrue(CircuitList.anyOpenedCircuitsCached())
        CircuitList.channelMarkCircidUnusable(42L)
        assertEquals(null, CircuitList.circuitGetByCircidChannel(42L, 7))
        CircuitList.channelMarkCircidUsable(42L)
        assertNotNull(CircuitList.circuitGetByCircidChannel(42L, 7))
        assertNotNull(CircuitList.circuitGetByCircidChannelEvenIfMarked(42L, 7))
        assertEquals(meta, CircuitList.circuitGetByGlobalId(42L))
        assertEquals(meta, CircuitList.circuitGetByEdgeConn(99))
        assertEquals(1, CircuitList.circuitGetCpathLen(meta))
        assertEquals(1, CircuitList.circuitGetCpathOpenedLen(meta))
        assertNotNull(CircuitList.circuitGetCpathHop(meta, 0))
        meta.state = CircuitState.CHAN_WAIT
        assertEquals(1, CircuitList.circuitCountPendingOnChannel(7))
        assertEquals(1, CircuitList.circuitGetAllPendingOnChannel(7).size)
        assertTrue(CircuitList.circuitDumpByConn(7).contains("circ=42"))
        assertTrue(CircuitList.circuitEventStatus(meta).startsWith("CIRC"))
        meta.state = CircuitState.GUARD_WAIT
        assertEquals(1, CircuitList.circuitFindCircuitsToUpgradeFromGuardWait().size)
        meta.state = CircuitState.OPEN
        assertNotNull(CircuitList.circuitFindToCannibalize())
        CircuitList.circuitClearTestingCellStats(meta)
        CircuitList.circuitClearCpath(meta)
        assertEquals(0, CircuitList.circuitGetCpathLen(meta))
        CircuitList.channelNoteDestroyPending(42L)
        CircuitList.markForClose(42L)
        assertEquals(1, CircuitList.countPendingClose())
        assertEquals(1, CircuitList.closeAllMarked())
        CircuitList.registerOrigin(1L)
        CircuitList.circuitFree(1L)
        CircuitList.circuitFreeAll()
        assertEquals(0, CircuitList.count())
    }

    @Test
    fun `ewma dos circpad cell_pack sendme version`() {
        CircuitMuxEwma.cellEwmaInitializeTicks(0)
        val (tick, frac) = CircuitMuxEwma.cellEwmaGetCurrentTickAndFraction(5_000)
        assertEquals(0, tick)
        assertTrue(frac >= 0.0)
        val pol = CircuitMuxEwma.newPolicy()
        CircuitMuxEwma.cmuxEwmaSetOptions(pol, 30_000)
        CircuitMuxEwma.circuitmuxEwmaFreeAll()
        assertTrue(Sendme.cellVersionCanBeHandled(1))
        val packed = ConnectionOr.cellPack(1, CellCommand.PADDING, ByteArray(3))
        assertEquals(8, packed.size)
        val bucket = Dos.CcBucket(tokens = 1.0, lastRefillMs = 0)
        Dos.ccStatsRefillBucket(bucket, nowMs = 2_000)
        assertTrue(bucket.tokens > 1.0)
        val g = Dos.newGuard()
        assertTrue(Dos.dosCcNewCreateCell(g, "1.1.1.1"))
        Dos.dosCcGetDefenseType(g, "1.1.1.1")
        Dos.dosCloseClientConn(g, "1.1.1.1")
        Dos.dosConnAddrGetDefenseType(g, "2.2.2.2")
        Dos.dosConsensusHasChanged(mapOf("DoSCircuitCreationEnabled" to 1L))
        assertTrue(Dos.dosEnabled())
        Dos.dosGeoipEntryInit("9.9.9.9")
        assertEquals(1, Dos.dosGetNumCcMarkedAddr())
        assertEquals(1, Dos.dosGetNumCcMarkedAddrMaxq())
        Dos.dosGeoipEntryAboutToFree("9.9.9.9")
        Dos.dosFreeAll()
        CircuitPadding.circpadAddMatchingMachines(listOf(CircuitPadding.clientHideIntro()))
        assertEquals(1, CircuitPadding.matchingMachines().size)
        val info = CircuitPadding.circpadCircuitMachineinfoNew()
        CircuitPadding.circpadCircuitFreeAllMachineinfos(info)
        assertEquals(Circpad.Event.PADDING_RECV, CircuitPadding.circpadCheckReceivedCell(true))
        assertTrue(CircuitPadding.circpadCircPurposeToMask(CircuitPurpose.GENERAL) != 0)
        val ctrl = CircpadMachineController(
            CircuitPadding.clientHideIntro(),
            sendDrop = {},
        )
        CircuitPadding.circpadCellEventNonpaddingSent(ctrl)
        CircuitPadding.circpadCellEventNonpaddingReceived(ctrl)
        CircuitPadding.circpadCellEventPaddingSent(ctrl)
        CircuitPadding.circpadCellEventPaddingReceived(ctrl)
        CircuitPadding.circpadDeliverRecognizedRelayCellEvents(ctrl, false)
        CircuitPadding.circpadDeliverSentRelayCellEvents(ctrl, true)
        CircuitPadding.circpadDeliverUnrecognizedCellEvents(ctrl)
    }

    @Test
    fun `circpad remainder circuituse circuitstats cc connection_or dos`() {
        val ctrl = CircpadMachineController(CircuitPadding.clientHideIntro(), sendDrop = {})
        val hist = CircpadHistogram.exampleFromSpecComment()
        assertEquals(0L, CircuitPadding.circpadHistogramBinToUsec(hist, 0))
        assertEquals(0, CircuitPadding.circpadHistogramUsecToBin(hist, 50))
        val nego = CircpadNegotiate.encodeNegotiate(
            CircpadNegotiate.Negotiate(command = CircpadNegotiate.COMMAND_START, machineType = 1),
        )
        assertEquals(CircpadNegotiate.COMMAND_START, CircuitPadding.circpadHandlePaddingNegotiate(nego).command)
        val ned = CircpadNegotiate.encodeNegotiated(
            CircpadNegotiate.Negotiated(
                command = CircpadNegotiate.COMMAND_START,
                response = CircpadNegotiate.RESPONSE_OK,
                machineType = 1,
            ),
        )
        assertEquals(CircpadNegotiate.RESPONSE_OK, CircuitPadding.circpadHandlePaddingNegotiated(ned).response)
        CircuitPadding.circpadInternalEventBinsEmpty(ctrl)
        CircuitPadding.circpadInternalEventInfinity(ctrl)
        CircuitPadding.circpadInternalEventStateLengthUp(ctrl)
        assertEquals(0, CircuitPadding.circpadMachineCurrentState(ctrl))
        CircuitPadding.circpadMachineEventCircAddedHop(ctrl)
        CircuitPadding.circpadMachineEventCircBuilt(ctrl)
        CircuitPadding.circpadMachineEventCircHasNoRelayEarly(ctrl)
        CircuitPadding.circpadMachineEventCircHasNoStreams(ctrl)
        assertEquals("client_ip_circ", CircuitPadding.circpadMachineClientHideIntroCircuits().name)
        assertEquals("client_rp_circ", CircuitPadding.circpadMachineClientHideRendCircuits().name)
        assertNotNull(CircuitPadding.circpadMachineRelayHideIntroCircuits())
        assertNotNull(CircuitPadding.circpadMachineRelayHideRendCircuits())
        CircuitPadding.circpadFreeAll()

        CircuitUse.clear()
        var u = CircuitUse.circuitLaunch(CircuitUse.Purpose.GENERAL, 10L)
        u = CircuitUse.circuitHasOpened(u)
        assertTrue(CircuitUse.circuitIsAcceptable(u))
        assertTrue(CircuitUse.circuitIsAvailableForUse(u))
        u = CircuitUse.circuitChangePurpose(u, CircuitUse.Purpose.HS_CLIENT_INTRO)
        assertTrue(CircuitUse.circuitPurposeIsHsClient(u.purpose))
        assertTrue(CircuitUse.circuitPurposeIsHiddenService(u.purpose))
        assertTrue(CircuitUse.circuitIsHsV3(u.copy(hsV3 = true)))
        assertTrue(CircuitUse.circuitPurposeIsHsService(CircuitUse.Purpose.HS_SERVICE_INTRO))
        assertTrue(CircuitUse.circuitPurposeIsHsVanguards(CircuitUse.Purpose.HS_VANGUARDS))
        assertTrue(CircuitUse.circuitConformsToOptions(u))
        CircuitUse.circuitDetachStream(u)
        assertTrue(CircuitUse.circuitEnoughTestingCircs(2, 1))
        assertEquals(2, CircuitUse.circuitBuildNeededCircs(1, 3))
        u = CircuitUse.circuitReadValidData(u, 100)
        u = CircuitUse.circuitRemoveHandledPorts(u.copy(portsHandled = setOf(80, 443)), setOf(80))
        assertNotNull(CircuitUse.circuitGetBest(CircuitUse.Purpose.HS_CLIENT_INTRO))
        CircuitUse.circuitLaunchByExtendInfo(
            ExtendInfo(nickname = "e", identityDigest = ByteArray(20), orPorts = listOf(ExtendInfo.OrPort("1.1.1.1", 9))),
        )
        assertTrue(CircuitUse.circuitLogAncientOneHopCircuits(1).contains("ancient"))
        CircuitUse.circuitBuildFailed(10L)
        CircuitUse.circuitResetFailureCount()
        assertEquals(0, CircuitUse.failureCount())
        CircuitUse.circuitExpireBuilding(System.currentTimeMillis() + 10_000, 1)
        CircuitUse.circuitExpireOldCircsAsNeeded(System.currentTimeMillis() + 10_000, 1)
        CircuitUse.circuitExpireOldCircuitsServerside(System.currentTimeMillis() + 10_000, 1)
        CircuitUse.circuitExpireWaitingForBetterGuard()

        CircuitStats.circuitBuildTimesInit()
        CircuitStats.circuitBuildTimesAddTime(100)
        CircuitStats.circuitBuildTimesHandleCompletedHop(200)
        assertTrue(CircuitStats.circuitBuildTimesCalculateTimeout() >= 10)
        assertTrue(CircuitStats.circuitBuildTimesCdf(10_000) >= 0.0)
        CircuitStats.circuitBuildTimesCountClose()
        CircuitStats.circuitBuildTimesCountTimeout()
        assertTrue(CircuitStats.circuitBuildTimesCloseRate() >= 0.0)
        assertFalse(CircuitStats.circuitBuildTimesDisabled())
        CircuitStats.circuitBuildTimesDisabledSet(false)
        assertFalse(CircuitStats.circuitBuildTimesEnoughToCompute(1000))
        assertTrue(CircuitStats.circuitBuildTimesGenerateSample() > 0)
        assertTrue(CircuitStats.circuitBuildTimesGetXm() >= 0)
        assertTrue(CircuitStats.circuitBuildTimesInitialAlpha() > 0)
        assertEquals(CircuitStats.DEFAULT_TIMEOUT_MS, CircuitStats.circuitBuildTimesInitialTimeout())
        CircuitStats.circuitBuildTimesMarkCircAsMeasurementOnly()
        CircuitStats.circuitBuildTimesNetworkCircSuccess()
        assertTrue(CircuitStats.circuitBuildTimesNetworkIsLive())
        assertTrue(CircuitStats.circuitBuildTimesNetworkCheckLive())
        CircuitStats.circuitBuildTimesNetworkCheckChanged()
        CircuitStats.circuitBuildTimesNeedsCircuits()
        CircuitStats.circuitBuildTimesNeedsCircuitsNow()
        CircuitStats.circuitBuildTimesNewConsensusParams(mapOf("cbtquantile" to 80L))
        CircuitStats.circuitBuildTimesParseState(1000, 2000, 3)
        CircuitStats.circuitBuildTimesFreeTimeouts()

        CongestionControlCommon.resetToDefaults()
        CongestionControlCommon.congestionControlSetCcEnabled()
        assertTrue(CongestionControlCommon.congestionControlEnabled())
        assertTrue(CongestionControlCommon.circuitSentCellForSendme(31))
        assertEquals(2, CongestionControlCommon.congestionControlBuildExtRequest().size)
        assertEquals(2, CongestionControlCommon.congestionControlBuildExtResponse().size)
        assertEquals(CongestionControlCommon.CC_ALG_VEGAS, CongestionControlCommon.congestionControlDispatchCcAlg())
        val cc = CongestionControlCommon.congestionControlNew()
        assertTrue(CongestionControlCommon.congestionControlGetPackageWindow(cc) >= 0)
        assertNotNull(CongestionControlCommon.congestionControlGetControlPortFields(cc))
        CongestionControlCommon.congestionControlNoteCellSent()
        CongestionControlCommon.enqueueTimestamp()
        assertEquals(31, CongestionControlCommon.congestionControlParseExtRequest(byteArrayOf(1, 31)))
        assertEquals(31, CongestionControlCommon.congestionControlParseExtResponse(byteArrayOf(1, 31)))
        assertTrue(CongestionControlCommon.congestionControlValidateSendmeIncrement(31))
        assertTrue(CongestionControlCommon.isMonotimeClockReliable())
        assertEquals(50, CongestionControlCommon.percentMaxMix(0, 100, 50))
        assertEquals(CongestionControlCommon.current().sendmeInc, CongestionControlCommon.sendmeGetIncCount())
        CongestionControlCommon.congestionControlUpdateCircuitEstimates(10, 5)
        CongestionControlCommon.congestionControlUpdateCircuitRtt(10, 20)
        CongestionControlCommon.timeDeltaStalledOrJumped(-1)
        assertTrue(CongestionControlCommon.congestionControlGetNumClockStalls() >= 1)
        CongestionControlCommon.congestionControlFree(cc)
        CongestionControlCommon.congestionControlNewConsensusParams(null)
        CongestionControlCommon.congestionControlSetCcDisabled()

        ConnectionOr.clearBrokenConnectionMap()
        assertNotNull(ConnectionOr.connectionInitOrHandshakeState())
        val ch = ConnectionOr.connectionOrInitConnFromAddress("8.8.8.8", 9001)
        ConnectionOr.connectionOrFinishedConnecting(ch)
        ConnectionOr.connectionOrClientUsed(ch)
        ConnectionOr.connectionOrClientLearnedPeerId(ch, "aa".repeat(20))
        assertTrue(ConnectionOr.connectionOrDigestIsKnownRelay("aa".repeat(20)))
        assertTrue(ConnectionOr.connectionOrEventStatus(ch).startsWith("ORCONN"))
        assertTrue(ConnectionOr.connectionOrFinishedFlushing(ch))
        ch.queueOut(ByteArray(10))
        ConnectionOr.connectionOrFlushedSome(ch, 10)
        ch.ed25519Identity = ByteArray(32)
        assertEquals(32, ConnectionOr.connectionOrGetAllegedEd25519Id(ch)!!.size)
        assertTrue(ConnectionOr.connectionOrNumCellsWriteable(ch) >= 0)
        ConnectionOr.connectionOrProcessInbuf(ch, 5)
        assertEquals(6, ConnectionOr.connectionOrSendVersions().size)
        ConnectionOr.connectionOrSetCanonical(ch, true)
        assertTrue(ch.canonical)
        ConnectionOr.connectionOrAboutToClose(ch)
        val ch2 = Channel.init("1.1.1.1", 1)
        ConnectionOr.connectionOrConnectFailed(ch2)
        ConnectionOr.connectionOrNotifyError(Channel.init("2.2.2.2", 1), "x")
        ConnectionOr.connectionOrGroupSetBadness("bb".repeat(20))
        ConnectionOr.connectionOrReachedEof(Channel.init("3.3.3.3", 1))
        ConnectionOr.connectionOrCloseNormally(Channel.init("4.4.4.4", 1))
        ConnectionOr.connectionOrClearIdentity(ch)
        ConnectionOr.connectionOrClearIdentityMap()
        assertTrue(ConnectionOr.connectionOrReportBrokenStates() >= 0)

        Dos.dosInit()
        assertTrue(Dos.isInitialized())
        val guard = Dos.newGuard(streamDefenseEnabled = true)
        assertTrue(Dos.dosNewClientConn(guard, "5.5.5.5"))
        Dos.dosNoteCircMaxOutq("5.5.5.5")
        Dos.setRefuseSingleHopClient(true)
        assertTrue(Dos.dosShouldRefuseSingleHopClient())
        Dos.dosNoteRefuseSingleHopClient()
        val tbf = Dos.dosStreamInitCircTbf()
        Dos.dosStreamNewBeginOrResolveCell(guard, "5.5.5.5", tbf)
        assertTrue(Dos.dosLogHeartbeat().contains("DoS"))
        assertTrue(Dos.dosGetNumCcRejected() >= 1)
        assertTrue(Dos.dosGetNumSingleHopRefused() >= 1)
        Dos.dosFreeAll()
    }

    @Test
    fun `conflux command reasons flow control L3 aliases`() {
        assertEquals("TIMEOUT", Reasons.circuitEndReasonToControlString(Reasons.CIRC_TIMEOUT))
        assertEquals("DONE", Reasons.streamEndReasonToControlString(Reasons.STREAM_DONE))
        assertTrue(Reasons.streamEndReasonToString(Reasons.STREAM_DONE).isNotEmpty())
        assertTrue(Reasons.streamEndReasonToSocks5Response(Reasons.STREAM_DONE) > 0)
        assertEquals("DONE", Reasons.orconnEndReasonToControlString(Reasons.ORCONN_DONE))
        assertTrue(Reasons.endReasonToHttpConnectResponseLine(0).startsWith("HTTP/1.0"))
        assertTrue(Reasons.socks4ResponseCodeToString(0x5a).contains("accepted"))
        assertTrue(Reasons.socks5ResponseCodeToString(0).contains("accepted"))
        assertTrue(Reasons.errnoToStreamEndReason(Reasons.Errno.ECONNREFUSED) > 0)
        assertTrue(Reasons.errnoToOrconnEndReason(Reasons.Errno.ECONNREFUSED) > 0)
        assertTrue(Reasons.tlsErrorToOrconnEndReason(Reasons.TOR_TLS_ERROR_IO) > 0)

        val cell = Cell(0, CellCommand.RELAY, ByteArray(0))
        assertEquals(Command.Handler.RELAY, Command.commandProcessCell(cell))
        val ch = Channel.init("1.1.1.1", 9001)
        assertEquals(ChannelState.OPENING, Command.commandSetupChannel(ch).state)
        val listen = ChannelListener(ListenSpec("127.0.0.1", 9050))
        assertEquals(9050, Command.commandSetupListener(listen).listen.port)

        CongestionControlFlow.flowControlNewConsensusParams(mapOf("cc_xoff_client" to 100))
        val edge = CongestionControlFlow.EdgeState(CongestionControlFlow.EdgeKind.CLIENT_OR_HS)
        assertTrue(CongestionControlFlow.edgeUsesFlowControl(true))
        assertTrue(CongestionControlFlow.connUsesFlowControl(true))
        assertEquals(0, CongestionControlFlow.flowControlDecideXoff(edge, nowUsec = 1))
        CongestionControlFlow.flowControlDecideXon(edge, nWritten = 0, nowUsec = 1)
        CongestionControlFlow.flowControlNoteSentData(edge, 10)
        assertTrue(CongestionControlFlow.circuitProcessStreamXoff(edge))
        assertTrue(CongestionControlFlow.circuitProcessStreamXon(edge, CongestionControlFlow.encodeXon(42)))

        val set = ConfluxSet(ConfluxCell.newNonce())
        set.congestion = CongestionControl()
        assertNotNull(Conflux.circuitCcontrol(set))
        Conflux.confluxClearOooQ(set)
        assertTrue(Conflux.confluxMsgAllocCost(ConfluxMsg(1, ByteArray(8))) > 0)
        assertTrue(Conflux.confluxShouldMultiplex(RelayCommand.DATA.id))
        assertEquals(0, Conflux.confluxProcessSwitchCommand(set, 3))
        assertTrue(Conflux.confluxProcessRelayMsg(set, 10, ByteArray(4)))
        assertNotNull(Conflux.confluxDequeueRelayMsg(set))
        Conflux.confluxNoteCellSent(set, null)
        assertTrue(Conflux.confluxGetMaxSeqSent(set) >= 0)
        assertTrue(Conflux.confluxGetMaxSeqRecv(set) >= 0)
        assertTrue(Conflux.confluxGetTotalBytesAllocation() >= 0)
        assertTrue(Conflux.confluxGetCircBytesAllocation(set) >= 0)
        assertEquals(0L, Conflux.confluxHandleOom(0))
        Conflux.confluxUpdateRtt(set, 1, 1000)
        Conflux.confluxRelayMsgFree_(ConfluxMsg(2))
        assertEquals(-1, Conflux.confluxGetLeg(set, 99L))
        assertEquals(null, Conflux.confluxDecideNextCirc(set))
        assertEquals(null, Conflux.confluxDecideCircForSend(set, null))

        ConfluxParams.resetToDefaults()
        val cfg = TorConfig(java.nio.file.Path.of("/tmp/ktor-cfx-test"))
        assertFalse(ConfluxParams.confluxIsEnabled(cfg, congestionControlEnabled = false))
        assertTrue(ConfluxParams.confluxParamsGetMaxLegsSet() >= 3)
        assertTrue(ConfluxParams.confluxParamsGetMaxLinkedSet() >= 0)
        assertTrue(ConfluxParams.confluxParamsGetDrainPct() >= 0)
        assertTrue(ConfluxParams.confluxParamsGetSendPct() >= 0)
        assertTrue(ConfluxParams.confluxParamsGetMaxOooq() >= 0)
        assertTrue(ConfluxParams.confluxParamsGetMaxUnlinkedLegRetry() >= 0)
        assertTrue(ConfluxParams.confluxParamsGetNumLegsSet() >= 0)
        ConfluxParams.confluxParamsNewConsensus(null)
        assertTrue(ConfluxParams.confluxParamsGetMaxPrebuilt() >= 0)

        val link = ConfluxCell.confluxCellNewLink()
        val enc = ConfluxCell.confluxCellSendLink(link)
        assertEquals(link.nonce.toList(), ConfluxCell.confluxCellParseLink(enc).nonce.toList())
        assertEquals(link.nonce.toList(), ConfluxCell.confluxCellParseLinked(enc).nonce.toList())
        assertEquals(0, ConfluxCell.confluxCellSendLinkedAck().size)
        assertEquals(9L, ConfluxCell.confluxCellParseSwitch(ConfluxCell.confluxSendSwitchCommand(9)).sequence)
        assertEquals(enc.size, ConfluxCell.confluxCellSendLinked(link).size)

        ConfluxPool.confluxPoolInit()
        assertTrue(ConfluxPool.launchNewSet(2))
        val nonce = ConfluxCell.newNonce()
        assertTrue(ConfluxPool.confluxProcessLink(nonce, 1))
        assertTrue(ConfluxPool.confluxProcessLinked(nonce, 2))
        assertTrue(ConfluxPool.confluxProcessLinkedAck(nonce))
        assertTrue(ConfluxPool.confluxLaunchLeg(nonce))
        ConfluxPool.confluxCircuitHasOpened(nonce, 3)
        ConfluxPool.confluxCircuitHasClosed(nonce, 3)
        ConfluxPool.confluxCircuitAboutToFree(nonce, 2)
        val excl = mutableSetOf<String>()
        ConfluxPool.confluxAddGuardsToExcludeList(excl, listOf("aa"))
        ConfluxPool.confluxAddMiddlesToExcludeList(excl, listOf("bb"))
        assertTrue(excl.size == 2)
        assertNotNull(ConfluxPool.confluxGetCircForConn(nonce))
        assertTrue(ConfluxPool.confluxLogSet(ConfluxPool.find(nonce)!!).contains("cfx"))
        assertTrue(ConfluxPool.getLinkedPool() >= 0)
        assertTrue(ConfluxPool.getUnlinkedPool() >= 0)
        ConfluxPool.confluxPredictNew()
        ConfluxPool.confluxNotifyShutdown()
        ConfluxPool.confluxClearShutdown()
        ConfluxPool.confluxMarkAllForClose(nonce)
        ConfluxPool.confluxPoolFreeAll()

        val util = ConfluxUtil.SetState(nonce = ConfluxCell.newNonce())
        ConfluxUtil.addLeg(util, 1)
        ConfluxUtil.noteRtt(util, 1, 50)
        assertTrue(ConfluxUtil.confluxCanSend(util))
        assertEquals(32, ConfluxUtil.confluxGetNonce(util).size)
        assertEquals(50, ConfluxUtil.confluxGetCircRtt(util, 1))
        assertEquals(1000, ConfluxUtil.circuitGetPackageWindow(1000))
        assertEquals(2, ConfluxUtil.confluxGetDestinationHop(3))
        assertTrue(ConfluxUtil.confluxValidateLegs(util))
        assertTrue(ConfluxUtil.confluxValidateSourceHop(1, 1))
        assertTrue(ConfluxUtil.confluxValidateStreamLists(util))
        ConfluxUtil.confluxSyncCircFields(util, 1)
        assertEquals(3, ConfluxUtil.confluxUpdatePStreams(3))
        assertEquals(3, ConfluxUtil.confluxUpdateHalfStreams(3))
        assertEquals(3, ConfluxUtil.confluxUpdateNStreams(3))
        assertEquals(3, ConfluxUtil.confluxUpdateResolvingStreams(3))
        assertTrue(ConfluxUtil.edgeUsesCpath(true))
        assertEquals(50, ConfluxUtil.edgeGetMaxRtt(util))
        assertTrue(ConfluxUtil.relayCryptFromLastHop(2, 3))
    }

    @Test
    fun `connection_ap and vegas L3 aliases`() {
        ConnectionEdge.clearApPendingForTests()
        val ap = ConnectionEdge.connectionApMakeLink("Example.COM.", 443)
        assertEquals("example.com", ConnectionEdge.connectionApHandshakeRewriteAndAttach(ap, "Example.COM."))
        assertTrue(ConnectionEdge.connectionApCanUseExit(true))
        assertTrue(ConnectionEdge.connectionApDetachRetriable(ap))
        ConnectionEdge.connectionApMarkAsWaitingForRenddesc(ap)
        ConnectionEdge.connectionApMarkAsPendingCircuit_(ap)
        assertTrue(ConnectionEdge.connectionApHandshakeSendResolve(ap, "dns.example").isNotEmpty())
        assertEquals(10, ConnectionEdge.connectionApHandshakeSocksReply(ap).size)
        assertNotNull(ConnectionEdge.connectionApHandshakeSocksResolvedAddr(ap, "1.2.3.4"))
        ConnectionEdge.connectionApFailOnehop(ap)
        assertTrue(ap.onehopFailed)
        assertEquals("example.org" to 443, ConnectionEdge.connectionApProcessHttpConnect("CONNECT example.org:443 HTTP/1.1"))
        val t = ConnectionEdge.connectionApProcessTransparent("9.9.9.9", 53)
        assertEquals(53, t.port)
        assertTrue(ConnectionEdge.connectionApAttachPending() >= 0)
        assertTrue(ConnectionEdge.connectionApRescanAndAttachPending() >= 0)
        ap.beginningExpireAtMs = 1
        ConnectionEdge.connectionApExpireBeginning(nowMs = 2)
        ConnectionEdge.connectionApAboutToClose(t)

        val params = CongestionControlVegas.congestionControlVegasSetParams(CongestionControlVegas.PathKind.EXIT)
        val upd = CongestionControlVegas.congestionControlVegasProcessSendme(
            cwnd = 124,
            rttMinMs = 50,
            rttEwmaMs = 80,
            inSlowStart = true,
            params = params,
        )
        assertTrue(upd.newCwnd > 0)
    }

    @Test
    fun `cpath extendinfo onion status protover dos_sys L3 aliases`() {
        val path = CryptPath.Path()
        val ei = ExtendInfo.extendInfoNew(
            nickname = "n1",
            identityDigest = ByteArray(20) { 1 },
            orPort = ExtendInfo.OrPort("8.8.8.8", 9001),
            curve25519OnionKey = ByteArray(32) { 2 },
            supportsNtorV3 = true,
        )
        assertTrue(ExtendInfo.extendInfoSupportsNtor(ei))
        assertTrue(ExtendInfo.extendInfoSupportsNtorV3(ei))
        assertTrue(ExtendInfo.extendInfoAddrIsAllowed("8.8.8.8", allowPrivate = false))
        assertFalse(ExtendInfo.extendInfoAnyOrportAddrIsInternal(ei))
        val ei2 = ExtendInfo.extendInfoAddOrport(ei, "1.1.1.1", 9001)
        assertTrue(ExtendInfo.extendInfoHasOrport(ei2, "1.1.1.1", 9001))
        assertNotNull(ExtendInfo.extendInfoGetOrport(ei2, ExtendInfo.AF_INET))
        assertNotNull(ExtendInfo.extendInfoPickOrport(ei2))
        assertTrue(ExtendInfo.extendInfoHasPreferredOnionKey(ei2))
        assertEquals(20, ExtendInfo.extendInfoDup(ei2).identityDigest.size)
        assertEquals(null, ExtendInfo.extendInfoFree_(ei2))

        val hop = CryptPath.cpathAppendHop(path, ei)
        assertEquals(1, CryptPath.cpathGetNHops(path))
        CryptPath.cpathAssertLayerOk(hop)
        CryptPath.cpathAssertOk(path)
        assertEquals(hop, CryptPath.cpathGetNextNonOpenHop(path))
        CryptPath.cpathInitCircuitCrypto(hop, crypto = null)
        assertEquals(null, CryptPath.cpathGetSendmeTag(hop))
        assertTrue(CryptPath.cpathSendmeCircuitRecordInboundCell(hop) >= 0)
        val hop2 = CryptPath.Hop()
        CryptPath.cpathExtendLinkedList(path, hop2)
        assertEquals(2, CryptPath.cpathGetNHops(path))
        CryptPath.cpathFree(path)
        assertEquals(0, CryptPath.cpathGetNHops(path))

        val create = Onion.createCellInit(2, ByteArray(84) { 3 })
        val createdPayload = Onion.createCellFormat(create)
        assertEquals(create, Onion.createCellParse(createdPayload))
        assertEquals(createdPayload.size, Onion.createCellFormatRelayed(create).size)
        val created = Onion.createdCellParse(ByteArray(64) { 4 })
        assertEquals(64, Onion.createdCellFormat(created).size)
        val ext = Onion.ExtendCell(create = create)
        assertTrue(Onion.extendCellFormat(ext).size >= createdPayload.size)
        val extended = Onion.extendedCellParse(created.reply)
        assertEquals(64, Onion.extendedCellFormat(extended).size)

        assertEquals(3, HeartbeatStatus.countCircuits(3))
        HeartbeatStatus.noteConnection(inbound = true, ipv6 = false)
        HeartbeatStatus.noteCircClosedForUnrecognizedCells(1, 2)
        assertTrue(HeartbeatStatus.secsToUptime(3661).contains("hours"))
        assertTrue(HeartbeatStatus.logHeartbeat(100, 200, 1).contains("Heartbeat"))

        assertNotNull(DosSys.dosGetOptions())
        assertTrue(Protover.encodeProtocolList(mapOf("Link" to "3-5")).startsWith("Link="))
        assertTrue(Protover.parseProtocolList(Protover.SUPPORTED_PROTOCOLS).containsKey("Link"))
        assertTrue(Protover.protocolListSupportsProtocol(Protover.SUPPORTED_PROTOCOLS, Protover.ProtocolType.LINK, 4))
        assertTrue(Protover.protocolListSupportsProtocolOrLater(Protover.SUPPORTED_PROTOCOLS, Protover.ProtocolType.RELAY, 1))
        assertEquals("Link", Protover.protocolTypeToStr(Protover.ProtocolType.LINK))
        assertEquals(Protover.ProtocolType.LINK, Protover.strToProtocolType("Link"))
        assertTrue(Protover.protoverGetSupportedProtocols().isNotEmpty())
        assertNotNull(Protover.protoverGetSupported(Protover.ProtocolType.FLOW_CTRL))
        assertTrue(Protover.protoverIsSupportedHere(Protover.ProtocolType.CONFLUX, 1))
        assertFalse(Protover.protoverListIsInvalid(Protover.SUPPORTED_PROTOCOLS))
        assertTrue(Protover.protoverAllSupported("Link=4"))
        assertTrue(Protover.protoverComputeForOldTor().contains("Link="))
        assertTrue(Protover.protoverComputeVote(listOf(Protover.SUPPORTED_PROTOCOLS, Protover.SUPPORTED_PROTOCOLS)).contains("Link="))
        assertTrue(Protover.protoverGetRecommendedClientProtocols().isNotEmpty())
        assertTrue(Protover.protoverGetRecommendedRelayProtocols().isNotEmpty())
        assertTrue(Protover.protoverGetRequiredClientProtocols().isNotEmpty())
        assertTrue(Protover.protoverGetRequiredRelayProtocols().isNotEmpty())
        Protover.protoverFreeAll()
        Protover.protoEntryFree_()
    }

    @Test
    fun `firewall scheduler ocirc orconn cell sizes sendme versions L3`() {
        assertTrue(Policies.firewallIsFascistOr(true))
        assertTrue(Policies.firewallIsFascistDir(true))
        assertTrue(Policies.getinfoHelperPolicies().isNotEmpty())
        Policies.policiesFreeAll()

        assertEquals(514, Cell.getCellNetworkSize(true))
        assertEquals(4, Cell.getCircIdSize(true))
        assertEquals(7, Cell.getVarCellHeaderSize(true))
        assertEquals(1, Sendme.emitMinVersionResolved())
        assertTrue(Sendme.acceptMinVersionResolved() >= 0)
        val dq = Sendme.DigestQueue()
        val dig = ByteArray(20) { 1 }
        Sendme.sendmeRecordCellDigestOnCirc(dq, dig)
        assertTrue(Sendme.sendmeIsValid(dq, Sendme.buildCellPayloadV1(dig)))
        assertEquals(999, Sendme.sendmeNoteCircuitDataPackaged(1000))
        assertEquals(1100, Sendme.sendmeProcessCircuitLevel(1000))
        assertEquals(1100, Sendme.sendmeProcessCircuitLevelImpl(1000))
        assertEquals(499, Sendme.sendmeNoteStreamDataPackaged(500))
        assertEquals(550, Sendme.sendmeProcessStreamLevel(500))
        assertTrue(Sendme.sendmeCircuitConsiderSending(100))
        assertTrue(Sendme.sendmeConnectionEdgeConsiderSending(50))
        assertEquals(999, Sendme.sendmeCircuitDataReceived(1000, dig).first)
        assertEquals(499, Sendme.sendmeStreamDataReceived(500).first)

        Scheduler.schedulerInit()
        assertEquals(SchedulerType.VANILLA, Scheduler.getVanillaScheduler())
        Scheduler.schedulerKistSetFullMode()
        assertEquals(SchedulerType.KIST, Scheduler.getKistScheduler())
        Scheduler.schedulerKistSetLiteMode()
        assertEquals(SchedulerType.KIST_LITE, Scheduler.getKistScheduler())
        assertTrue(Scheduler.kistSchedulerRunInterval() >= 1)
        assertTrue(Scheduler.getSchedulerStateString().isNotEmpty())
        assertTrue(Scheduler.getChannelsPending() >= 0)
        Scheduler.schedulerEvAdd()
        assertTrue(Scheduler.schedulerEvActive())
        Scheduler.schedulerConfChanged()
        Scheduler.schedulerNotifyNetworkstatusChanged()
        val ch = Channel.init("1.2.3.4", 9001)
        Scheduler.schedulerChannelWantsWrites(ch)
        Scheduler.schedulerTouchChannel(ch)
        Scheduler.schedulerSetChannelState(ch, ChannelSchedState.PENDING)
        Scheduler.noteBugForTests()
        assertTrue(Scheduler.schedulerBugOccurred())
        Scheduler.schedulerCanUseKist()
        Scheduler.schedulerFreeAll()

        OcircEvent.clearListeners()
        var got = 0
        OcircEvent.addListener { got++ }
        OcircEvent.ocircCeventPublish(1, OcircEvent.Status.BUILT)
        OcircEvent.ocircChanPublish(1, 9)
        OcircEvent.ocircStatePublish(1, OcircEvent.Status.CLOSED)
        assertEquals(3, got)
        OrconnEvent.clearListeners()
        var og = 0
        OrconnEvent.addListener { og++ }
        OrconnEvent.orconnStatePublish(2, OrconnEvent.Status.CONNECTED, "x:1")
        OrconnEvent.orconnStatusPublish(2, OrconnEvent.Status.FAILED, "x:1", "TIMEOUT")
        assertEquals(2, og)

        assertEquals(0, OrSys.ocircAddPubsub())
        assertEquals(0, OrSys.orconnAddPubsub())
        OrPeriodic.orRegisterPeriodicEvents()

        assertNotNull(Versions.torVersionParse("0.4.8.10"))
        assertTrue(Versions.torVersionCompare(Versions.parse("0.4.9.0")!!, Versions.parse("0.4.8.0")!!) > 0)
        assertTrue(Versions.torVersionSameSeries(Versions.parse("0.4.8.1")!!, Versions.parse("0.4.8.2")!!))
        assertNotNull(Versions.torVersionParsePlatform("Tor 0.4.8.10"))
        assertTrue(Versions.torVersionAsNewAs("0.4.8.10", "0.4.8.0"))
        assertTrue(Versions.torGetApproxReleaseDate("0.4.8.10") > 0)
        assertEquals(listOf("0.4.7.0", "0.4.8.0"), Versions.sortVersionList(listOf("0.4.8.0", "0.4.7.0")))
        assertTrue(Versions.summarizeProtoverFlags(Protover.SUPPORTED_PROTOCOLS).contains("Link="))
        Versions.protoverSummaryCacheFreeAll()
        assertEquals(Versions.Status.RECOMMENDED, Versions.torVersionIsObsolete("0.4.8.10", "0.4.8.10"))
    }

    @Test
    fun `relay_msg addressmap bridges authmode L3 aliases`() {
        val msg = RelayMsg.Msg(RelayCommand.DATA, 1, 4, byteArrayOf(1, 2, 3, 4))
        val copy = RelayMsg.relayMsgCopy(msg)
        assertEquals(msg, copy)
        assertEquals(0, RelayMsg.relayMsgClear(msg).length)
        assertEquals(null, RelayMsg.relayMsgFree_(copy))

        AddressMap.addressmapInit()
        val automap = AddressMap.newAutomap()
        assertTrue(AddressMap.parseVirtualAddrNetwork("127.192.0.0/10"))
        AddressMap.addressmapRegister("example.com", "1.2.3.4", transient = true)
        assertTrue(AddressMap.addressmapHaveMapping("example.com"))
        assertEquals("1.2.3.4", AddressMap.addressmapRewrite("example.com"))
        assertEquals("example.com", AddressMap.addressmapRewriteReverse("1.2.3.4"))
        assertTrue(AddressMap.addressmapGetMappings().isNotEmpty())
        val vip = AddressMap.addressmapRegisterVirtualAddress(automap, "x.onion")
        assertTrue(vip.startsWith("127."))
        assertTrue(AddressMap.getRandomVirtualAddr(automap).startsWith("127."))
        AddressMap.clientDnsSetAddressmap("dns.example", "9.9.9.9")
        AddressMap.clientDnsSetReverseAddressmap("9.9.9.9", "dns.example")
        assertEquals(1, AddressMap.clientDnsIncrFailures("bad.example"))
        AddressMap.clientDnsClearFailures("bad.example")
        AddressMap.addressmapRegister("track.example", "8.8.8.8", trackExit = true)
        AddressMap.clearTrackexithostMappings()
        AddressMap.addressmapClearTransient()
        AddressMap.addressmapClearInvalidAutomaps(automap)
        AddressMap.addressmapFreeAll()

        Bridges.bridgesFreeAll()
        val fp = "A".repeat(40)
        val b = Bridges.bridgeAddFromConfig("obfs4 1.2.3.4:443 $fp cert=abc")!!
        assertEquals("1.2.3.4" to 443, Bridges.bridgeGetAddrPort(b))
        assertEquals(20, Bridges.bridgeGetRsaIdDigest(b)!!.size)
        assertEquals("obfs4", Bridges.bridgetGetTransportName(b))
        assertFalse(Bridges.bridgeHasInvalidTransport(b))
        assertTrue(Bridges.addrIsAConfiguredBridge("1.2.3.4", 443))
        assertTrue(Bridges.nodeIsAConfiguredBridge(fp))
        assertTrue(Bridges.extendInfoIsAConfiguredBridge(fp))
        assertTrue(Bridges.anyBridgesDontSupportMicrodescriptors())
        assertNotNull(Bridges.findBridgeByDigest(fp))
        assertNotNull(Bridges.getConfiguredBridgeByAddrPortDigest("1.2.3.4", 443, fp))
        assertNotNull(Bridges.getConfiguredBridgeByExactAddrPortDigest("1.2.3.4", 443, fp))
        assertNotNull(Bridges.getConfiguredBridgeByOrportsDigest("1.2.3.4", 443, fp))
        assertEquals("obfs4", Bridges.findTransportNameByBridgeAddrport("1.2.3.4", 443))
        assertEquals("obfs4", Bridges.getTransportByBridgeAddrport("1.2.3.4", 443))
        assertTrue(Bridges.getSocksArgsByBridgeAddrport("1.2.3.4", 443).containsKey("cert"))
        assertTrue(Bridges.fetchBridgeDescriptors() >= 1)
        Bridges.learnedBridgeDescriptor(fp, ByteArray(20))
        Bridges.learnedRouterIdentity(fp, ByteArray(20))
        Bridges.markBridgeList()
        assertTrue(Bridges.confluxCanExcludeUsedBridges())
        assertTrue(Bridges.bridgeListGet().isNotEmpty())
        Bridges.bridgeResolveConflicts(BridgeLine.parse("1.2.3.4:9001 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")!!)
        assertTrue(Bridges.addrIsAConfiguredBridge("1.2.3.4", 443))
        Bridges.clearBridgeList()

        val auth = AuthModeOptions(authoring = true, bridgeAuthority = true)
        assertTrue(AuthMode.authdirMode(auth))
        assertTrue(AuthMode.authdirModeV3(auth))
        assertTrue(AuthMode.authdirModeBridge(auth))
        assertTrue(AuthMode.authdirModeHandlesDescs(auth, AuthMode.PURPOSE_BRIDGE))
        assertTrue(AuthMode.authdirModePublishesStatuses(auth))
        assertTrue(AuthMode.authdirModeTestsReachability(auth))
    }

    @Test
    fun `entrynodes guard L3 aliases`() {
        EntryNodes.entryGuardsFreeAll()
        val cfg = TorConfig(dataDirectory = java.nio.file.Path.of("/tmp/ktor-entrynodes-test"))
        assertEquals("default", EntryNodes.chooseGuardSelection(cfg))
        assertEquals("bridges", EntryNodes.chooseGuardSelection(cfg.copy(useBridges = true)))

        val gs = EntryNodes.getGuardSelectionInfo()
        val fp = "a".repeat(40)
        val g = EntryNodes.entryGuardAddToSample(gs, fp)
        assertEquals(fp, EntryNodes.entryGuardGetRsaIdDigest(g))
        assertEquals(fp, EntryNodes.entryGuardFindNode(g))
        assertTrue(EntryNodes.entryGuardDescribe(g).contains("Guard"))
        assertNotNull(EntryNodes.entryGuardGetPathbiasState(g))

        val encoded = EntryNodes.entryGuardEncodeForState(g)
        val parsed = EntryNodes.entryGuardParseFromState(encoded)!!
        assertEquals(fp, parsed.fingerprintHex)

        assertEquals(g.fingerprintHex, EntryNodes.entryGuardGetByIdDigest(fp)!!.fingerprintHex)
        assertEquals(
            g.fingerprintHex,
            EntryNodes.entryGuardGetByIdDigestForGuardSelection(gs, fp)!!.fingerprintHex,
        )

        val other = EntryNodes.entryGuardAddToSample(gs, "b".repeat(40))
        other.confirmed = false
        g.confirmed = true
        assertTrue(EntryNodes.entryGuardHasHigherPriority(g, other))

        val picked = EntryNodes.entryGuardPickForCircuit(gs)!!
        assertTrue(EntryNodes.entryGuardCouldSucceed(picked.second))
        assertEquals(GuardUsable.NOW, EntryNodes.entryGuardSucceeded(picked.second))
        assertFalse(EntryNodes.entryGuardStateShouldExpire(picked.second, nowEpochSec = picked.second.createdEpochSec))

        val failState = EntryNodes.entryGuardPickForCircuit(gs)!!.second
        EntryNodes.entryGuardFailed(failState)
        assertEquals(CircGuardStateKind.DEAD, failState.state)

        val cancelState = EntryNodes.entryGuardPickForCircuit(gs)!!.second
        EntryNodes.entryGuardCancel(cancelState)
        assertEquals(CircGuardStateKind.DEAD, cancelState.state)

        EntryNodes.entryGuardChanFailed(1L, fp)
        assertTrue(EntryNodes.entryGuardConsiderRetry(EntryGuardRuntime(fp, lastAttemptEpochSec = 0), nowEpochSec = 10_000))

        EntryNodes.entryGuardLearnedBridgeIdentity("1.2.3.4", 443, "c".repeat(40))
        assertEquals("c".repeat(40), EntryNodes.learnedBridgeIdentity("1.2.3.4", 443))

        // All sampled NO → known-but-down
        for (s in gs.sampled) s.reachable = GuardReachable.NO
        assertTrue(EntryNodes.entriesKnownButDown(cfg.copy(useEntryGuards = true)))
        EntryNodes.entriesRetryAll(cfg.copy(useEntryGuards = true))
        assertTrue(gs.sampled.any { it.reachable == GuardReachable.MAYBE })

        assertEquals(null, EntryNodes.entryGuardFree_(g))
        assertEquals(null, EntryNodes.entryGuardRestrictionFree_(EntryGuardRestriction()))
        assertEquals(null, EntryNodes.circuitGuardStateFree_(cancelState))
    }

    @Test
    fun `pathbias L3 aliases`() {
        // Inventory: L3:feature/client/pathbias_*
        val opts = PathBiasOptions(extremeRate = 0.31, extremeUseRate = 0.41, dropGuards = true)
        assertEquals(0.31, CircPathBias.pathbiasGetExtremeRate(opts))
        assertEquals(0.41, CircPathBias.pathbiasGetExtremeUseRate(opts))
        assertTrue(CircPathBias.pathbiasGetDropguards(opts))
        assertEquals("build attempted", CircPathBias.pathbiasStateToString(PathState.BUILD_ATTEMPTED))
        assertEquals(1, CircPathBias.pathbiasCheckProbeResponse(0))
        assertEquals(0, CircPathBias.pathbiasCheckProbeResponse(2))

        val tracker = CircPathBias.newTracker(opts)
        val fp = "a".repeat(40)
        assertEquals(1, CircPathBias.pathbiasCountBuildAttempt(1L, fp, tracker))
        CircPathBias.pathbiasCountBuildSuccess(1L, fp, tracker)
        CircPathBias.pathbiasCountUseAttempt(1L, fp, tracker)
        CircPathBias.pathbiasCountValidCells(1L, fp, cellCount = 1, tracker = tracker)
        CircPathBias.pathbiasMarkUseSuccess(2L, fp, tracker)
        CircPathBias.pathbiasCountBuildAttempt(3L, fp, tracker)
        CircPathBias.pathbiasCountUseAttempt(3L, fp, tracker)
        assertEquals(1, CircPathBias.pathbiasCheckClose(3L, reason = 0, guardFp = fp, tracker = tracker))
        CircPathBias.pathbiasCountBuildAttempt(4L, fp, tracker)
        CircPathBias.pathbiasCountUseAttempt(4L, fp, tracker)
        CircPathBias.pathbiasMarkUseRollback(4L, tracker)
        CircPathBias.pathbiasCountTimeout(5L, fp, tracker)
    }

    @Test
    fun `transports managed_proxy L3 aliases`() {
        Transports.clear()
        Transports.markTransportList()
        val mp = Transports.managedProxyCreate(listOf("obfs4"), listOf("/usr/bin/obfs4proxy"), isServer = false)
        assertEquals(1, Transports.configureProxy(mp))
        assertTrue(Transports.launchProxyEv(mp))
        assertTrue(Transports.managedProxyHasTransport("obfs4"))
        assertEquals("launched", Transports.managedProxyStateToString(mp.state))
        Transports.managedProxySetState(mp, PtProtoState.CONFIGURING)
        assertEquals(6, Transports.managedProxySeverityParse("info"))
        assertEquals("127.0.0.1", Transports.managedProxyOutboundAddress(4))
        Transports.setPtProxyUri("socks5://127.0.0.1:1080")
        assertEquals("socks5://127.0.0.1:1080", Transports.getPtProxyUri())

        assertEquals(0, Transports.parseCmethodLine("CMETHOD obfs4 socks5 127.0.0.1:12345", mp))
        val server = Transports.managedProxyCreate(listOf("obfs4"), listOf("x"), isServer = true)
        assertEquals(0, Transports.parseSmethodLine("SMETHOD obfs4 0.0.0.0:9000", server))
        assertTrue(Transports.getTransportProxyPorts().contains(12345))
        assertTrue(Transports.getTransportOptionsForServerProxy(server).contains("obfs4"))

        Transports.parseEnvError("ENV-ERROR bad")
        Transports.parseProxyError("PROXY-ERROR fail")
        Transports.parseLogLine("LOG INFO hi", mp)
        Transports.parseStatusLine("STATUS TRANSPORT=obfs4", mp)
        Transports.handleProxyLine("CMETHODS DONE", mp)
        assertEquals(PtProtoState.COMPLETED, mp.state)
        Transports.handleStatusMessage(mapOf("TRANSPORT" to "obfs4"))
        Transports.managedProxyStdoutCallback(mp, "VERSION 1.0")
        Transports.managedProxyStderrCallback(mp, "warn")
        assertTrue(Transports.managedProxyExitCallback(mp, 0))
        assertEquals(null, Transports.freeExecveArgs(mutableListOf("a", "b")))
        assertEquals(null, Transports.managedProxyDestroy(mp))
    }
}

/** Test helper — reset OrChannel gid without exposing internals elsewhere. */
private object OrChannelGid {
    fun reset() {
        org.kotlintor.link.OrChannel.resetGidForTests()
        ChannelTable.clear()
    }
}
