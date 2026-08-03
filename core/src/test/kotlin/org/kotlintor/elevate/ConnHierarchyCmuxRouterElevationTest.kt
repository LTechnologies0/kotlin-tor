package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.cell.Cell
import org.kotlintor.cell.CellCodec
import org.kotlintor.cell.CellCommand
import org.kotlintor.circuit.CircuitMux
import org.kotlintor.circuit.EwmaCircuitMuxPolicy
import org.kotlintor.config.IsolationFlag
import org.kotlintor.config.TorrcParser
import org.kotlintor.dir.RouterList
import org.kotlintor.dir.RouterStatus
import org.kotlintor.link.ConnectionCast
import org.kotlintor.link.ConnectionState
import org.kotlintor.link.ConnectionTable
import org.kotlintor.link.ConnectionType
import org.kotlintor.link.SchedulerType
import org.kotlintor.link.WriteBudget
import java.nio.file.Path

class ConnHierarchyCmuxRouterElevationTest {
    @Test
    fun `connection hierarchy entry control dir exit linked`() {
        ConnectionTable.clear()
        val or = ConnectionTable.newOr("1.2.3.4", 9001, isClient = false)
        or.markHandshaking()
        or.markOpen()
        val entry = ConnectionTable.newEntry("127.0.0.1", 4050, socksUser = "u1", isolationKey = "u1")
        entry.originalDest = "example.com:443"
        entry.markOpen()
        val exit = ConnectionTable.newExit("93.184.216.34", 443, streamId = 7, circId = 42)
        exit.markOpen()
        entry.linkTo(exit)
        val ctrl = ConnectionTable.newControl("127.0.0.1", 9051)
        ctrl.authenticated = true
        ctrl.markOpen()
        val dir = ConnectionTable.newDir("199.58.81.140", 80, purpose = "consensus")
        dir.markOpen()
        val ext = ConnectionTable.newExtOr("127.0.0.1", 666)
        ext.transportName = "obfs4"
        ext.markOpen()
        val listener = ConnectionTable.newListener("127.0.0.1", 9001, ConnectionType.OR)
        listener.markOpen()

        assertEquals(7, ConnectionTable.countOpen())
        assertNotNull(ConnectionCast.toOr(or))
        assertNotNull(ConnectionCast.toEntry(entry))
        assertNotNull(ConnectionCast.toExit(exit))
        assertNotNull(ConnectionCast.toControl(ctrl))
        assertNotNull(ConnectionCast.toDir(dir))
        assertNotNull(ConnectionCast.toExtOr(ext))
        assertNotNull(ConnectionCast.toListener(listener))
        assertEquals(exit.id, ConnectionTable.linkedPeer(entry)?.id)
        assertEquals(entry.id, ConnectionTable.linkedPeer(exit)?.id)
        assertEquals(ConnectionState.OPEN, or.state)
        ConnectionTable.clear()
        assertEquals(0, ConnectionTable.count())
    }

    @Test
    fun `live cmux enqueue drain under KIST budget`() {
        val mux = CircuitMux(EwmaCircuitMuxPolicy(halfLifeSec = 30.0))
        val budget = WriteBudget(SchedulerType.KIST_LITE, tickBudgetBytes = 514)
        mux.attach(1)
        mux.attach(2)
        val cell1 = CellCodec.encode(Cell(1, CellCommand.RELAY, ByteArray(Cell.FIXED_PAYLOAD_LEN)), 4)
        val cell2 = CellCodec.encode(Cell(2, CellCommand.RELAY, ByteArray(Cell.FIXED_PAYLOAD_LEN)), 4)
        assertTrue(mux.enqueue(1, cell1))
        assertTrue(mux.enqueue(2, cell2))
        assertEquals(2, mux.numCells())
        budget.refill(null)
        var flushed = 0
        while (mux.numCells() > 0) {
            budget.refill(null)
            val item = mux.flushNext() ?: break
            check(item is CircuitMux.FlushItem.Cell)
            if (!budget.tryAllowFull(item.payload.size)) {
                mux.enqueue(item.circId, item.payload)
                continue
            }
            flushed++
        }
        assertEquals(2, flushed)
        assertEquals(0, mux.numCells())
    }

    @Test
    fun `HS DirGroupReadable ExportCircuitID and Isolate standalone keys`() {
        val cfg = TorrcParser.parse(
            """
            DataDirectory /tmp/kt
            IsolateSOCKSAuth 1
            IsolateDestAddr 1
            HiddenServiceDir /tmp/kt/hs
            HiddenServicePort 80 127.0.0.1:8080
            HiddenServiceDirGroupReadable 1
            HiddenServiceExportCircuitID haproxy
            """.trimIndent(),
            Path.of("/tmp/kt"),
        )
        assertTrue(IsolationFlag.IsolateSOCKSAuth in cfg.isolationFlags)
        assertTrue(IsolationFlag.IsolateDestAddr in cfg.isolationFlags)
        val hs = cfg.hiddenServices.single()
        assertTrue(hs.dirGroupReadable)
        assertEquals("haproxy", hs.exportCircuitId)
    }

    @Test
    fun `RouterList filterExclude and pickDistinct`() {
        val list = RouterList()
        fun rs(nick: String, fp: Byte, flags: Set<String>, bw: Long) = RouterStatus(
            nickname = nick,
            identity = ByteArray(20) { fp },
            digest = ByteArray(20),
            publication = java.time.Instant.parse("2020-01-01T00:00:00Z"),
            ip = "1.2.3.${fp.toInt() and 0xff}",
            orPort = 9001,
            dirPort = 0,
            flags = flags,
            version = null,
            proto = emptyMap(),
            bandwidth = bw,
        )
        list.add(rs("A", 1, setOf("Running", "Fast", "Guard"), 1000))
        list.add(rs("B", 2, setOf("Running", "Fast", "Exit"), 2000))
        list.add(rs("C", 3, setOf("Running", "Fast", "Exit", "Guard"), 3000))
        assertEquals(2, list.exits().size)
        assertEquals(2, list.guards().size)
        val filtered = list.filterExclude(listOf(list.byNickname("A")!!.fingerprintHex))
        assertEquals(2, filtered.size)
        val picked = list.pickDistinct(2)
        assertEquals(2, picked.size)
        assertTrue(picked.map { it.fingerprintHex }.toSet().size == 2)
    }
}
