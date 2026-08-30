package org.kotlintor.elevate

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.kotlintor.circuit.CircuitKind
import org.kotlintor.circuit.CircuitList
import org.kotlintor.config.TorrcParser
import org.kotlintor.dir.DirAuthVoteGossip
import org.kotlintor.dir.DirAuthVoteInbox
import org.kotlintor.dir.DirCache
import org.kotlintor.link.ChannelScheduler
import org.kotlintor.link.SchedulerType
import org.kotlintor.link.WriteBudget
import org.kotlintor.net.AddressSet
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class DirAuthHttpAddressCircuitElevationTest {
    @Test
    fun `address set bloom contains inserted`() {
        val set = AddressSet(128)
        val a = InetAddress.getByName("198.51.100.9")
        assertFalse(set.probablyContains(a))
        set.add(a)
        assertTrue(set.probablyContains(a))
        set.addIpv4h(0xC0000201.toInt())
        assertTrue(set.probablyContains(InetAddress.getByName("192.0.2.1")))
    }

    @Test
    fun `circuit list tracks origin and or`() {
        CircuitList.clear()
        CircuitList.registerOrigin(42)
        CircuitList.registerOr(99, isExit = true)
        assertEquals(2, CircuitList.count())
        assertTrue(CircuitList.get(42)!!.isOrigin)
        assertTrue((CircuitList.get(99)!!.kind as CircuitKind.Or).isExit)
        CircuitList.remove(42)
        assertEquals(1, CircuitList.count())
    }

    @Test
    fun `torrc NewCircuitPeriod LearnCBT Schedulers`() {
        val cfg = TorrcParser.parse(
            """
            DataDirectory /tmp/ktor-opts
            NewCircuitPeriod 45
            LearnCircuitBuildTimeout 0
            Schedulers kist,vanilla
            """.trimIndent(),
            Path.of("/tmp/ktor-opts"),
        )
        assertEquals(45, cfg.newCircuitPeriodSec)
        assertFalse(cfg.learnCircuitBuildTimeout)
        // Full KIST opt-in only; default select falls through to VANILLA.
        assertEquals(SchedulerType.VANILLA, ChannelScheduler.select(cfg.schedulers))
    }

    @Test
    fun `write budget kist gates flush size`() {
        val wb = WriteBudget(SchedulerType.KIST_LITE, tickBudgetBytes = 100)
        wb.refill()
        assertTrue(wb.tryAllowFull(50))
        assertFalse(wb.tryAllowFull(60))
        assertTrue(wb.tryAllowFull(50))
    }

    @Test
    fun `dircache POST vote inbox`(@TempDir dir: Path) {
        val inbox = DirAuthVoteInbox()
        val cache = DirCache(dir, voteInbox = inbox)
        val vote = "network-status-version 3\nvote-status vote\n"
        val resp = cache.handleHttp(
            "POST /tor/post/vote HTTP/1.0\r\nX-Tor-Authority-Id: AABB\r\n\r\n",
            vote.toByteArray(StandardCharsets.UTF_8),
        )
        assertTrue(String(resp, StandardCharsets.UTF_8).startsWith("HTTP/1.0 200"))
        assertEquals(1, inbox.size())
        assertTrue(inbox.get("aabb")!!.contains("vote-status vote"))
    }

    @Test
    fun `http gossip posts vote to peer DirPort`(@TempDir dir: Path) = runBlocking {
        val inbox = DirAuthVoteInbox()
        val cache = DirCache(dir, voteInbox = inbox)
        val ready = CountDownLatch(1)
        val done = CountDownLatch(1)
        val ss = ServerSocket()
        ss.bind(InetSocketAddress("127.0.0.1", 0))
        val port = ss.localPort
        Executors.newSingleThreadExecutor().execute {
            ready.countDown()
            val sock = ss.accept()
            try {
                val input = sock.getInputStream()
                val header = java.io.ByteArrayOutputStream()
                val b = ByteArray(1)
                while (header.size() < 65536) {
                    if (input.read(b) <= 0) break
                    header.write(b[0].toInt())
                    val s = header.toString(StandardCharsets.US_ASCII)
                    if (s.contains("\r\n\r\n")) break
                }
                val headers = header.toString(StandardCharsets.US_ASCII)
                val len = headers.lineSequence()
                    .firstOrNull { it.startsWith("Content-Length:", ignoreCase = true) }
                    ?.substringAfter(':')?.trim()?.toIntOrNull() ?: 0
                val body = input.readNBytes(len)
                sock.getOutputStream().write(cache.handleHttp(headers, body))
            } finally {
                sock.close()
                ss.close()
                done.countDown()
            }
        }
        assertTrue(ready.await(2, TimeUnit.SECONDS))
        val vote = "network-status-version 3\nvote-status vote\n"
        val r = DirAuthVoteGossip.postVote("127.0.0.1", port, vote, fromFp = "CCDD")
        assertTrue(r.code in 200..299, "code=${r.code} body=${r.body}")
        assertTrue(done.await(2, TimeUnit.SECONDS))
        assertEquals(1, inbox.size())
    }
}
