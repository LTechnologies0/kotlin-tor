package org.kotlintor.dir

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.cell.Reasons
import org.kotlintor.compress.CompressMethod
import org.kotlintor.compress.CompressProvider
import org.kotlintor.compress.CompressionLevel
import org.kotlintor.compress.TorCompress
import org.kotlintor.compress.ZstdFrame
import org.kotlintor.path.EntryGuardFsm
import org.kotlintor.path.GuardReachable
import org.kotlintor.status.HeartbeatStatus
import java.nio.file.Files
import kotlin.coroutines.EmptyCoroutineContext

class DirAuthEntryGuardReasonsTest {
    @Test
    fun `entry guard fsm prefer yes`() {
        val fsm = EntryGuardFsm(retryIntervalSec = 10)
        fsm.noteAttempt("aa", nowEpochSec = 0)
        fsm.noteFailure("aa", nowEpochSec = 1)
        assertEquals(GuardReachable.NO, fsm.getOrCreate("aa").reachable)
        fsm.noteSuccess("bb", nowEpochSec = 2)
        assertEquals("bb", fsm.pickPreferred(listOf("aa", "bb")))
        assertFalse(fsm.considerRetry("aa", nowEpochSec = 5))
        assertTrue(fsm.considerRetry("aa", nowEpochSec = 20))
    }

    @Test
    fun `reasons tables`() {
        assertEquals("TORPROTOCOL", Reasons.circuitEndToControl(1))
        assertEquals("EXITPOLICY", Reasons.streamEndToControl(Reasons.STREAM_EXITPOLICY))
        assertEquals(Reasons.SOCKS5_NOT_ALLOWED, Reasons.streamEndToSocks5(Reasons.STREAM_EXITPOLICY))
        assertEquals(Reasons.SOCKS5_CONNECTION_REFUSED, Reasons.streamEndToSocks5(Reasons.STREAM_DONE))
        assertEquals("DONE", Reasons.orconnEndToControl(Reasons.ORCONN_DONE))
        assertEquals("CONNECTRESET", Reasons.orconnEndToControl(Reasons.ORCONN_CONNRESET))
    }

    @Test
    fun `compress provider registration`() {
        val identityZstd = object : CompressProvider {
            override val method: CompressMethod = CompressMethod.ZSTD
            override fun compress(input: ByteArray, level: CompressionLevel): ByteArray =
                byteArrayOf(0x28, 0xB5.toByte(), 0x2F, 0xFD.toByte()) + input
            override fun uncompress(input: ByteArray): ByteArray = input.copyOfRange(4, input.size)
        }
        TorCompress.registerProvider(identityZstd)
        try {
            assertTrue(TorCompress.supports(CompressMethod.ZSTD))
            val raw = "hello".toByteArray()
            val c = TorCompress.compress(raw, CompressMethod.ZSTD)
            assertTrue(ZstdFrame.looksLike(c))
            assertEquals("hello", String(TorCompress.uncompress(c)))
        } finally {
            TorCompress.unregisterProvider(CompressMethod.ZSTD)
        }
        assertFalse(TorCompress.supports(CompressMethod.ZSTD))
    }

    @Test
    fun `heartbeat format`() {
        HeartbeatStatus.resetClock()
        val line = HeartbeatStatus.format(1, 2, true, circuitsOpen = 3)
        assertTrue(line.contains("Heartbeat:"))
        assertTrue(line.contains("circuits=3"))
    }

    @Test
    fun `dirauth publish loop dumps bridges`() {
        val dir = Files.createTempDirectory("ktor-da")
        val scope = CoroutineScope(EmptyCoroutineContext + Dispatchers.Unconfined)
        val loop = DirAuthPublishLoop(
            scope = scope,
            dataDir = dir,
            timing = DirVote.Timing(voteIntervalSec = 300, voteSeconds = 10, distSeconds = 10, testing = true),
            knownAuthorities = setOf("aa".repeat(20)),
        )
        loop.noteBridge(
            BridgeAuth.BridgeStatus(
                identityHex = "bb".repeat(20),
                nickname = "b1",
                ip = "1.2.3.4",
                orPort = 443,
                flags = setOf("Running"),
            ),
        )
        loop.dumpBridges()
        assertTrue(Files.exists(dir.resolve("networkstatus-bridges")))
        scope.cancel()
    }
}
