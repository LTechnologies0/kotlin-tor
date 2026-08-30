package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.kotlintor.cell.Cell
import org.kotlintor.cell.CellCommand
import org.kotlintor.cell.ProtoCell
import org.kotlintor.cell.RelayCell
import org.kotlintor.cell.RelayCommand
import org.kotlintor.cell.RelayMsg
import org.kotlintor.circuit.CircuitStats
import org.kotlintor.circuit.CircuitUse
import org.kotlintor.circuit.Command
import org.kotlintor.crypto.OnionCrypto
import org.kotlintor.dir.Versions
import org.kotlintor.mainloop.Periodic
import org.kotlintor.os.CpuWorker
import org.kotlintor.pt.ProtoExtOr
import org.kotlintor.relay.OrPeriodic
import java.io.ByteArrayInputStream
import java.util.concurrent.TimeUnit

/**
 * Elevates:
 * - L1:core/crypto/onion_crypto.c
 * - L1:core/mainloop/cpuworker.c
 * - L1:core/mainloop/periodic.c
 * - L1:core/or/versions.c
 * - L1:core/or/or_periodic.c
 * - L1:core/or/circuitstats.c
 * - L1:core/or/circuituse.c
 * - L1:core/or/command.c
 * - L1:core/or/relay_msg.c
 * - L1:core/proto/proto_cell.c
 * - L1:core/proto/proto_ext_or.c
 */
class OnionCryptoCpuWorkerVersionsElevationTest {
    @BeforeEach
    fun reset() {
        CpuWorker.freeAll()
        Periodic.shutdown()
        CircuitStats.reset()
    }

    @Test
    fun `onion_crypto create_fast roundtrip`() {
        assertTrue(OnionCrypto.isSupported(OnionCrypto.HandshakeType.FAST))
        assertEquals("fast", OnionCrypto.handshakeName(OnionCrypto.HandshakeType.FAST))
        val (st, skin) = OnionCrypto.onionSkinCreateFast()
        val (reply, server) = OnionCrypto.onionSkinServerFast(skin)
        val client = OnionCrypto.onionSkinClientFast(st, reply)
        assertArrayEquals(server.kh, client.kh)
    }

    @Test
    fun `cpuworker queue work`() {
        assertEquals(0, CpuWorker.init(2))
        assertTrue(CpuWorker.isInitialized())
        assertEquals(2, CpuWorker.getNThreads())
        val f = CpuWorker.queueWork { 21 * 2 }!!
        assertEquals(42, f.get(2, TimeUnit.SECONDS))
        assertTrue(CpuWorker.estimatedUsecForOnionskins(3, 0x0002) > 0)
        CpuWorker.freeAll()
        assertFalse(CpuWorker.isInitialized())
    }

    @Test
    fun `versions parse and obsolete`() {
        val v = Versions.parse("Tor 0.4.8.12")!!
        assertEquals(0, v.major)
        assertEquals(4, v.minor)
        assertEquals(8, v.micro)
        assertEquals(12, v.patchLevel)
        assertEquals(Versions.Status.RECOMMENDED, Versions.isObsolete("0.4.8.12", "0.4.8.10,0.4.8.12"))
        assertEquals(Versions.Status.EMPTY, Versions.isObsolete("0.4.8.12", ""))
        assertTrue(Versions.asNewAs("0.4.8.12", "0.4.8.0"))
    }

    @Test
    fun `proto_cell encode decode`() {
        val cell = Cell(7, CellCommand.PADDING, ByteArray(10) { 1 })
        val bytes = ProtoCell.encode(cell)
        val round = ProtoCell.read(ByteArrayInputStream(bytes))
        assertEquals(7, round.circId)
        assertEquals(CellCommand.PADDING, round.command)
        assertEquals(4, ProtoCell.circIdLenForLinkProtocol(5))
    }

    @Test
    fun `proto_ext_or frame`() {
        val wire = ProtoExtOr.encode(0x0001, byteArrayOf(9, 8, 7))
        val (cmd, rest) = ProtoExtOr.fetchFromBuffer(wire + byteArrayOf(1, 2))!!
        assertEquals(1, cmd.cmd)
        assertArrayEquals(byteArrayOf(9, 8, 7), cmd.body)
        assertArrayEquals(byteArrayOf(1, 2), rest)
    }

    @Test
    fun `periodic and or_periodic`() {
        OrPeriodic.registerDefaults()
        assertTrue(Periodic.isInitialized())
        assertTrue(Periodic.registeredNames().contains("check_descriptor"))
        val ran = OrPeriodic.runDue(1_000_000L)
        assertTrue(ran.isNotEmpty())
        assertTrue(OrPeriodic.scheduleHints().contains("check_reachability"))
    }

    @Test
    fun `circuitstats timeout quantile`() {
        repeat(20) { CircuitStats.noteBuildTime(100L + it * 10) }
        assertTrue(CircuitStats.sampleCount() >= 20)
        assertTrue(CircuitStats.timeoutMs() >= 100)
        assertTrue(CircuitStats.snapshot().numCircs >= 20)
    }

    @Test
    fun `circuituse attach stream dirty`() {
        val clean = CircuitUse.UseState()
        assertTrue(CircuitUse.canAttachStream(clean, 1000, 60_000))
        val dirty = CircuitUse.markDirty(clean, 1000)
        assertTrue(CircuitUse.canAttachStream(dirty, 2000, 60_000))
        assertFalse(CircuitUse.canAttachStream(dirty, 100_000, 60_000))
        assertTrue(CircuitUse.isHsPurpose(CircuitUse.Purpose.HS_CLIENT_REND))
    }

    @Test
    fun `command classify`() {
        assertEquals(Command.Handler.CREATE, Command.classify(CellCommand.CREATE2))
        assertEquals(Command.Handler.RELAY, Command.classify(CellCommand.RELAY_EARLY))
        assertTrue(Command.isHandshakeCell(CellCommand.VERSIONS))
        assertTrue(Command.requiresCircuit(CellCommand.DESTROY))
    }

    @Test
    fun `relay_msg roundtrip`() {
        val cell = RelayCell(
            command = RelayCommand.DATA,
            recognized = 0,
            streamId = 42,
            digest = ByteArray(4),
            length = 3,
            data = byteArrayOf(1, 2, 3),
        )
        val msg = RelayMsg.fromRelayCell(cell)
        assertEquals(42, msg.streamId)
        assertTrue(RelayMsg.isData(msg.command))
        val back = RelayMsg.toRelayCell(msg)
        assertEquals(RelayCommand.DATA, back.command)
        assertArrayEquals(byteArrayOf(1, 2, 3), back.data.copyOf(3))
    }
}
