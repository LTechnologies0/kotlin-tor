package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.kotlintor.circuit.ConnectionEdge
import org.kotlintor.circuit.ConfluxSys
import org.kotlintor.circuit.EdgeStreamState
import org.kotlintor.circuit.Onion
import org.kotlintor.control.OcircEvent
import org.kotlintor.control.OrconnEvent
import org.kotlintor.crypto.OnionCrypto
import org.kotlintor.link.SchedulerVanilla
import org.kotlintor.net.Policies
import org.kotlintor.relay.Dos
import org.kotlintor.relay.DosConfig

/**
 * Elevates:
 * - L1:core/or/onion.c
 * - L1:core/or/dos.c
 * - L1:core/or/dos_config.c
 * - L1:core/or/ocirc_event.c
 * - L1:core/or/orconn_event.c
 * - L1:core/or/policies.c
 * - L1:core/or/conflux_sys.c
 * - L1:core/or/connection_edge.c
 * - L1:core/or/scheduler_vanilla.c
 */
class OnionDosPoliciesEventsElevationTest {
    @BeforeEach
    fun reset() {
        OcircEvent.clearListeners()
        OrconnEvent.clearListeners()
        SchedulerVanilla.reset()
        ConfluxSys.shutdown()
    }

    @Test
    fun `onion create2 encode parse`() {
        val skin = ByteArray(20) { it.toByte() }
        val wire = Onion.encodeCreate2(OnionCrypto.HandshakeType.FAST, skin)
        val cell = Onion.parseCreate2(wire)!!
        assertEquals(OnionCrypto.HandshakeType.FAST, cell.handshakeType)
        assertArrayEquals(skin, cell.onionSkin)
        assertEquals("fast", Onion.handshakeTypeName(cell.handshakeType))
    }

    @Test
    fun `dos and dos_config`() {
        val opts = DosConfig.fromTorConfigHints(connectionMax = 2, createRate = 5, createBurst = 2)
        assertTrue(DosConfig.validate(opts))
        val g = Dos.fromOptions(opts)
        assertTrue(Dos.allowConnection(g, "198.51.100.1"))
        assertTrue(Dos.allowConnection(g, "198.51.100.1"))
        assertFalse(Dos.allowConnection(g, "198.51.100.1"))
    }

    @Test
    fun `ocirc and orconn events`() {
        val seen = mutableListOf<String>()
        OcircEvent.addListener { seen += OcircEvent.formatControl(it) }
        OrconnEvent.addListener { seen += OrconnEvent.formatControl(it) }
        OcircEvent.emitBuilt(9, "a,b,c")
        OrconnEvent.emitConnected(3, "127.0.0.1:9001")
        assertTrue(seen.any { it.contains("CIRC 9 BUILT") })
        assertTrue(seen.any { it.contains("ORCONN") && it.contains("CONNECTED") })
    }

    @Test
    fun `policies fascist`() {
        val p = Policies.fascist(setOf(80, 443))
        assertTrue(Policies.allows(p, "1.1.1.1", 443))
        assertFalse(Policies.allows(p, "1.1.1.1", 22))
        val rule = Policies.parseLine("accept *:80")
        assertTrue(rule.accept)
    }

    @Test
    fun `conflux_sys init`() {
        assertEquals(0, ConfluxSys.initialize(true))
        assertTrue(ConfluxSys.isEnabled())
        ConfluxSys.shutdown()
        assertFalse(ConfluxSys.isEnabled())
    }

    @Test
    fun `connection_edge stream table`() {
        val t = ConnectionEdge.newTable()
        val s = t.open(1, 5, "example.com:80", isExit = false)
        assertEquals(EdgeStreamState.CONNECTING, s.state)
        t.markOpen(1, 5)
        assertEquals(1, t.countOpen())
        t.markEnd(1, 5)
        assertEquals(0, t.countOpen())
    }

    @Test
    fun `scheduler_vanilla pending`() {
        val a = SchedulerVanilla.ChannelRef(1, cellsQueued = 3, pending = true)
        val b = SchedulerVanilla.ChannelRef(2, cellsQueued = 1, pending = true)
        SchedulerVanilla.notePending(a)
        SchedulerVanilla.notePending(b)
        assertEquals(1, SchedulerVanilla.next()!!.id)
        assertTrue(SchedulerVanilla.pendingCount() >= 1)
    }
}
