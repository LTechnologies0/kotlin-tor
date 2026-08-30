package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.kotlintor.cell.CellCommand
import org.kotlintor.cell.RelayCommand
import org.kotlintor.circuit.CircuitBuild
import org.kotlintor.circuit.Conflux
import org.kotlintor.circuit.ExtendInfo
import org.kotlintor.circuit.Relay
import org.kotlintor.config.Statefile
import org.kotlintor.config.TorConfig
import org.kotlintor.link.Channel
import org.kotlintor.link.ConnectionModule
import org.kotlintor.link.ConnectionType
import org.kotlintor.mainloop.Mainloop
import org.kotlintor.mainloop.MainloopPubsub
import org.kotlintor.mainloop.MainloopSys
import org.kotlintor.net.AddressMap
import org.kotlintor.net.ProtoHttp
import org.kotlintor.net.ProtoSocks
import org.kotlintor.net.ResolveAddr
import org.kotlintor.net.Socks5Reply
import org.kotlintor.path.EntryNodes
import org.kotlintor.path.GuardReachable
import org.kotlintor.pt.Bridges
import org.kotlintor.pt.Transports
import java.nio.file.Files

/**
 * Elevates:
 * - L1:core/mainloop/connection.c
 * - L1:core/mainloop/mainloop.c
 * - L1:core/mainloop/mainloop_sys.c
 * - L1:core/mainloop/mainloop_pubsub.c
 * - L1:core/or/channel.c
 * - L1:core/or/circuitbuild.c
 * - L1:core/or/conflux.c
 * - L1:core/or/relay.c
 * - L1:app/config/resolve_addr.c
 * - L1:app/config/statefile.c
 * - L1:core/proto/proto_http.c
 * - L1:core/proto/proto_socks.c
 * - L1:feature/client/addressmap.c
 * - L1:feature/client/entrynodes.c
 * - L1:feature/client/bridges.c
 * - L1:feature/client/transports.c
 */
class MainloopChannelCircuitClientElevationTest {
    @BeforeEach
    fun reset() {
        ConnectionModule.clear()
        Channel.clear()
        MainloopSys.shutdown()
        MainloopPubsub.clear()
        Statefile.reset()
        ResolveAddr.resetSuggested()
        Transports.clear()
    }

    @Test
    fun `connection table`() {
        val or = ConnectionModule.newOr("127.0.0.1", 9001)
        or.markOpen()
        assertEquals(1, ConnectionModule.count())
        assertEquals(1, ConnectionModule.countOpen())
        assertEquals(1, ConnectionModule.byType(ConnectionType.OR).size)
        ConnectionModule.remove(or.id)
        assertEquals(0, ConnectionModule.count())
    }

    @Test
    fun `channel open queue`() {
        val ch = Channel.open("198.51.100.1", 443)
        assertTrue(Channel.queueCell(ch, ByteArray(514) { 1 }))
        assertEquals(1, Channel.count())
        assertEquals(1, Channel.openCount())
        Channel.close(ch)
        assertEquals(0, Channel.count())
    }

    @Test
    fun `mainloop sys pubsub`() {
        assertEquals(0, MainloopSys.initialize())
        assertTrue(MainloopSys.isInitialized())
        assertTrue(Mainloop.isRunning())
        Mainloop.tick()
        assertTrue(Mainloop.tickCount() >= 1)
        var hit = 0
        MainloopPubsub.subscribe("orconn") { hit++ }
        assertEquals(1, MainloopPubsub.publish("orconn", "x"))
        assertEquals(1, hit)
        MainloopSys.shutdown()
        assertFalse(Mainloop.isRunning())
    }

    @Test
    fun `circuitbuild plan`() {
        val hop = ExtendInfo(
            identityDigest = ByteArray(20) { 1 },
            orPorts = listOf(ExtendInfo.OrPort("1.1.1.1", 9001)),
            curve25519OnionKey = ByteArray(32) { 2 },
        )
        val plan = CircuitBuild.planThreeHop(hop, hop, hop)
        assertTrue(CircuitBuild.validatePlan(plan))
        assertEquals(3, CircuitBuild.hopCount(plan))
        assertTrue(CircuitBuild.validatePlan(CircuitBuild.planOneHop(hop)))
    }

    @Test
    fun `conflux and relay helpers`() {
        val nonce = Conflux.newNonce()
        assertEquals(32, nonce.size)
        assertTrue(Relay.isRelayCommand(CellCommand.RELAY_EARLY))
        assertTrue(Relay.isExtendFamily(RelayCommand.EXTEND2))
        assertTrue(Relay.isBeginFamily(RelayCommand.BEGIN_DIR))
    }

    @Test
    fun `resolve_addr and statefile`() {
        ResolveAddr.noteSuggested("203.0.113.10")
        assertEquals("203.0.113.10", ResolveAddr.suggested(ResolveAddr.Family.IPV4))
        val dir = Files.createTempDirectory("ktor-state")
        val p = dir.resolve("state")
        assertEquals(0, Statefile.load(p))
        Statefile.set("TorVersion", "0.4.8.0")
        assertTrue(Statefile.isDirty())
        assertEquals(0, Statefile.save())
        assertFalse(Statefile.isDirty())
        Statefile.reset()
        assertEquals(0, Statefile.load(p))
        assertEquals("0.4.8.0", Statefile.get("TorVersion"))
    }

    @Test
    fun `proto_http and proto_socks`() {
        val req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
            .toByteArray(Charsets.ISO_8859_1)
        assertTrue(ProtoHttp.isConnectMethod(req))
        assertNotNull(ProtoHttp.parseConnect(req))
        assertTrue(ProtoSocks.isSocks5Greeting(byteArrayOf(5, 1, 0)))
        val offer = ProtoSocks.parseMethodOffer(byteArrayOf(5, 1, 0))
        assertNotNull(offer)
        assertEquals(2, ProtoSocks.encodeMethodSelect(0).size)
        assertTrue(ProtoSocks.encodeReply(Socks5Reply.Succeeded).size >= 10)
    }

    @Test
    fun `addressmap entrynodes bridges transports`() {
        val map = AddressMap.newAutomap()
        assertTrue(AddressMap.shouldAutomap(map, "foo.onion"))
        val ip = AddressMap.getOrAssign(map, "foo.onion")
        assertEquals("foo.onion", AddressMap.reverse(map, ip))

        val cfg = TorConfig(dataDirectory = Files.createTempDirectory("ktor-eg"))
        assertTrue(EntryNodes.useEntryGuards(cfg))
        val fsm = EntryNodes.newFsm()
        fsm.noteSuccess("aabb")
        assertTrue(EntryNodes.confirmed(fsm.getOrCreate("aabb")))
        assertEquals(GuardReachable.YES, fsm.getOrCreate("aabb").reachable)

        val bl = Bridges.parseLine("obfs4 1.2.3.4:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA cert=x iat-mode=0")
        assertNotNull(bl)
        assertEquals("obfs4", Bridges.transportName(bl!!))
        assertTrue(Transports.register("obfs4"))
        assertTrue(Transports.isRegistered("obfs4"))
    }
}
