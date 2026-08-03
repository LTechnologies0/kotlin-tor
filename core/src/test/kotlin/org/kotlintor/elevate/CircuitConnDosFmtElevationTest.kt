package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.kotlintor.cell.CircuitPurpose
import org.kotlintor.circuit.CircuitKind
import org.kotlintor.circuit.CircuitMeta
import org.kotlintor.config.TorrcParser
import org.kotlintor.dir.FmtRouterStatus
import org.kotlintor.dir.RouterStatus
import org.kotlintor.dir.SharedRandom
import org.kotlintor.link.ConnectionState
import org.kotlintor.link.ConnectionTable
import org.kotlintor.link.ConnectionType
import org.kotlintor.relay.DosOptions
import java.nio.file.Path
import java.time.Instant

class CircuitConnDosFmtElevationTest {
    @Test
    fun `origin and or circuit kinds`() {
        val o = CircuitKind.Origin(circId = 7, purpose = CircuitPurpose.GENERAL, pathLength = 3)
        val meta = CircuitMeta(o)
        assertTrue(meta.isOrigin)
        assertFalse(meta.isOr)
        meta.kind = CircuitKind.Or(circId = 7, isExit = true, cryptoEstablished = true)
        assertTrue(meta.isOr)
        assertTrue((meta.kind as CircuitKind.Or).isExit)
    }

    @Test
    fun `connection table tracks or and ap`() {
        ConnectionTable.clear()
        val or = ConnectionTable.newOr("1.2.3.4", 9001, isClient = true)
        or.markOpen()
        or.noteWritten(100)
        assertEquals(1, ConnectionTable.countOpen())
        assertEquals(ConnectionType.OR, ConnectionTable.byType(ConnectionType.OR).single().type)
        ConnectionTable.remove(or.id)
        assertEquals(0, ConnectionTable.countOpen())
    }

    @Test
    fun `dos options from torrc`() {
        val cfg = TorrcParser.parse(
            """
            DataDirectory /tmp/ktor-dos
            DoSCircuitCreationEnabled 1
            DoSCircuitCreationRate 50
            DoSCircuitCreationBurst 4
            DoSConnectionMaxConcurrentCount 16
            MaxOnionQueueDelay 250
            CircuitPriorityHalflifeMsec 45000
            """.trimIndent(),
            Path.of("/tmp/ktor-dos"),
        )
        assertEquals(50, cfg.dosOptions.circuitCreationRate)
        assertEquals(4, cfg.dosOptions.circuitCreationBurst)
        assertEquals(16, cfg.dosOptions.connectionMaxConcurrent)
        assertEquals(250, cfg.maxOnionQueueDelayMs)
        assertEquals(45_000, cfg.circuitPriorityHalflifeMsec)
        val g = cfg.dosOptions.toGuard()
        assertTrue(g.allowConnection("10.0.0.1"))
    }

    @Test
    fun `dos options defaults match DosGuard`() {
        val o = DosOptions()
        assertTrue(o.circuitCreationEnabled)
        assertEquals(100, o.circuitCreationRate)
    }

    @Test
    fun `fmt routerstatus control port`(@TempDir dir: Path) {
        val rs = RouterStatus(
            nickname = "TestRelay",
            identity = ByteArray(20) { it.toByte() },
            digest = ByteArray(20) { (it + 1).toByte() },
            publication = Instant.parse("2024-01-02T03:04:05Z"),
            ip = "198.51.100.1",
            orPort = 9001,
            dirPort = 9030,
            flags = setOf("Fast", "Guard", "Running", "Stable", "Valid", "V2Dir"),
            version = "Tor 0.4.8.0",
            proto = mapOf("Link" to "1-5", "Relay" to "1-6"),
            bandwidth = 1000,
        )
        val text = FmtRouterStatus.formatEntry(rs, FmtRouterStatus.Format.CONTROL_PORT)
        assertTrue(text.startsWith("r TestRelay "))
        assertTrue(text.contains("\ns "))
        assertTrue(text.contains(" Fast"))
        assertTrue(text.contains(" Guard"))
        assertTrue(text.contains("\nv Tor 0.4.8.0\n"))
        assertTrue(text.contains("w Bandwidth=1000\n"))
        val micro = FmtRouterStatus.formatEntry(rs, FmtRouterStatus.Format.V3_CONSENSUS_MICRODESC)
        assertFalse(micro.contains("\ns "))
    }

    @Test
    fun `shared random state roundtrip`(@TempDir dir: Path) {
        val id = ByteArray(20) { 7 }
        val st = SharedRandom.State()
        st.put(SharedRandom.generateCommit(id))
        st.recompute()
        val path = dir.resolve("sr_state")
        st.save(path)
        val st2 = SharedRandom.State()
        st2.load(path)
        assertEquals(1, st2.all().size)
        assertTrue(st2.currentSrv!!.value.contentEquals(st.currentSrv!!.value))
    }
}
