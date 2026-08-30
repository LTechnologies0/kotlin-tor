package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.circuit.CircuitBuildRelay
import org.kotlintor.config.TorConfig
import org.kotlintor.dir.RouterInfo
import org.kotlintor.dir.RouterList
import org.kotlintor.dir.RouterSet
import org.kotlintor.dir.RouterStatus
import org.kotlintor.hs.HsCell
import org.kotlintor.hs.HsCircuit
import org.kotlintor.hs.HsCircuitmap
import org.kotlintor.hs.HsConfig
import org.kotlintor.hs.HsDescriptor
import org.kotlintor.hs.HsDos
import org.kotlintor.hs.HsIdent
import org.kotlintor.hs.HsIntropoint
import org.kotlintor.hs.HsMetrics
import org.kotlintor.hs.HsMetricsEntry
import org.kotlintor.hs.HsOb
import org.kotlintor.hs.HsPow
import org.kotlintor.hs.HsSys
import org.kotlintor.net.Dns
import org.kotlintor.relay.OnionQueue
import org.kotlintor.relay.RelayConfig
import org.kotlintor.relay.RelayFindAddr
import org.kotlintor.relay.RelayHandshake
import org.kotlintor.relay.RelayHandshakeState
import org.kotlintor.relay.RelayMetrics
import org.kotlintor.relay.RelayPeriodic
import org.kotlintor.relay.RelaySys
import org.kotlintor.relay.Router
import org.kotlintor.relay.TransportConfig
import org.kotlintor.stats.HsStats
import java.nio.file.Files
import java.time.Instant

/**
 * Elevates HS / relay / nodelist router* L1 units (D2→D3 naming primaries).
 */
class HsRelayNodelistElevationTest {
    @Test
    fun `hs config dos ident intro metrics sys`() {
        val c = TorConfig(dataDirectory = Files.createTempDirectory("ktor-hs-elev"))
        assertTrue(HsConfig.fromTorConfig(c).services.isEmpty())
        assertEquals(25, HsDos.DEFAULT_RATE)
        assertEquals("HS_INTRO", HsIdent.circuit(purpose = "HS_INTRO").purpose)
        val table = HsIntropoint.table()
        HsIntropoint.beginEstablish(table, "AA".repeat(32))
        assertEquals(1, table.size())
        HsMetrics.reset()
        HsMetrics.noteIntroReceived()
        assertEquals(1, HsMetrics.snapshot()["hs_intro_received"])
        assertTrue(HsMetricsEntry.KEYS.contains("hs_intro_received"))
        HsSys.init(c)
        HsSys.shutdown()
        assertFalse(HsSys.isStarted())
    }

    @Test
    fun `hs cell circuit map descriptor pow ob stats`() {
        assertTrue(HsCell.knownCommands().contains(HsCell.INTRODUCE2))
        assertTrue(HsCircuit.purposes().contains(HsCircuit.PURPOSE_CLIENT_REND))
        HsCircuitmap.clear()
        HsCircuitmap.put("tok", 7L)
        assertEquals(7L, HsCircuitmap.get("tok"))
        assertFalse(HsDescriptor.outerPresent(null))
        val ch = HsPow.challenge(effort = 0)
        val sol = HsPow.solve(ch, maxAttempts = 10)!!
        assertTrue(HsPow.verify(sol))
        val frontend = HsOb.generate()
        assertTrue(frontend.allowIntroduce())
        HsStats.noteIntroduce2Cell()
    }

    @Test
    fun `relay config addr sys periodic metrics handshake transport onion queue router`() {
        val c = TorConfig(dataDirectory = Files.createTempDirectory("ktor-relay-elev"))
        assertTrue(RelayConfig.fromTorConfig(c).validate().isNotEmpty()) // ORPort required
        RelayFindAddr.suggestAddresses(c)
        RelaySys.init(c)
        assertTrue(RelayPeriodic.scheduleHints(c).containsKey("republish_sec"))
        RelayMetrics.reset()
        RelayMetrics.noteCell()
        assertEquals(1L, RelayMetrics.snapshot()["relay_cells"])
        RelayHandshake.clear()
        RelayHandshake.noteState(RelayHandshakeState.VERSIONS)
        assertEquals(RelayHandshakeState.VERSIONS, RelayHandshake.lastStates().last())
        assertTrue(TransportConfig.parseListenLine("obfs4 0.0.0.0:443")!!.port == 443)
        val q = OnionQueue(maxPending = 2)
        assertTrue(q.tryEnqueue(1L, byteArrayOf(1)))
        assertEquals(1L, q.poll()!!.circId)
        assertFalse(Router.serverMode(c))
        RelaySys.shutdown()
    }

    @Test
    fun `nodelist routerlist routerset routerinfo dns circuitbuild_relay`() {
        assertEquals(0, RouterList().size())
        assertTrue(RouterSet("").isEmpty())
        val r = RouterStatus(
            nickname = "n",
            identity = ByteArray(20) { 0x0a },
            digest = ByteArray(20),
            publication = Instant.EPOCH,
            ip = "1.2.3.4",
            orPort = 9001,
            dirPort = 0,
            flags = setOf("Running"),
            version = null,
            proto = emptyMap(),
            bandwidth = 1,
        )
        assertEquals("n", RouterInfo.nickname(r))
        assertTrue(RouterInfo.isRunning(r))
        assertEquals(40, RouterInfo.fingerprint(r).length)
        assertTrue(Dns.isOnion("foo.onion"))
        assertEquals("bar", Dns.normalize(" Bar "))
        assertTrue(CircuitBuildRelay.knownCommands().contains(CircuitBuildRelay.EXTEND2))
    }
}
