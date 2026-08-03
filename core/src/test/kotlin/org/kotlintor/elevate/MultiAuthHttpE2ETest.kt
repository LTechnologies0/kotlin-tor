package org.kotlintor.elevate

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.kotlintor.config.TorrcParser
import org.kotlintor.dir.DirAuthVoteGossip
import org.kotlintor.dir.DirAuthVoteInbox
import org.kotlintor.dir.DirCache
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Two DirPort peers exchange votes over HTTP (multi-auth gossip E2E lite).
 */
class MultiAuthHttpE2ETest {
    @Test
    fun `two peers gossip votes over HTTP`(@TempDir dir: Path) = runBlocking {
        val inboxA = DirAuthVoteInbox()
        val inboxB = DirAuthVoteInbox()
        val cacheA = DirCache(dir.resolve("a"), voteInbox = inboxA)
        val cacheB = DirCache(dir.resolve("b"), voteInbox = inboxB)

        fun serve(cache: DirCache, latch: CountDownLatch): Pair<ServerSocket, Int> {
            val ss = ServerSocket()
            ss.bind(InetSocketAddress("127.0.0.1", 0))
            Executors.newSingleThreadExecutor().execute {
                latch.countDown()
                // Accept a few POSTs
                repeat(2) {
                    runCatching {
                        val sock = ss.accept()
                        try {
                            val input = sock.getInputStream()
                            val header = java.io.ByteArrayOutputStream()
                            val b = ByteArray(1)
                            while (header.size() < 65536) {
                                if (input.read(b) <= 0) break
                                header.write(b[0].toInt())
                                if (header.toString(StandardCharsets.US_ASCII).contains("\r\n\r\n")) break
                            }
                            val headers = header.toString(StandardCharsets.US_ASCII)
                            val len = headers.lineSequence()
                                .firstOrNull { it.startsWith("Content-Length:", ignoreCase = true) }
                                ?.substringAfter(':')?.trim()?.toIntOrNull() ?: 0
                            val body = input.readNBytes(len)
                            sock.getOutputStream().write(cache.handleHttp(headers, body))
                        } finally {
                            sock.close()
                        }
                    }
                }
                runCatching { ss.close() }
            }
            return ss to ss.localPort
        }

        val ready = CountDownLatch(2)
        val (_, portA) = serve(cacheA, ready)
        val (_, portB) = serve(cacheB, ready)
        assertTrue(ready.await(3, TimeUnit.SECONDS))

        val voteA = "network-status-version 3\nvote-status vote\nfingerprint AAAA\n"
        val voteB = "network-status-version 3\nvote-status vote\nfingerprint BBBB\n"
        val r1 = DirAuthVoteGossip.postVote("127.0.0.1", portB, voteA, fromFp = "AAAA")
        val r2 = DirAuthVoteGossip.postVote("127.0.0.1", portA, voteB, fromFp = "BBBB")
        assertTrue(r1.code in 200..299, "A→B ${r1.code} ${r1.body}")
        assertTrue(r2.code in 200..299, "B→A ${r2.code} ${r2.body}")
        assertEquals(1, inboxB.size())
        assertEquals(1, inboxA.size())
        assertTrue(inboxB.get("aaaa")!!.contains("AAAA"))
        assertTrue(inboxA.get("bbbb")!!.contains("BBBB"))
    }

    @Test
    fun `microdesc and assume-reachable torrc`() {
        val cfg = TorrcParser.parse(
            """
            DataDirectory /tmp/ktor-micro
            UseMicrodescriptors 0
            FetchUselessDescriptors 1
            DownloadExtraInfo 1
            AssumeReachable 1
            """.trimIndent(),
            Path.of("/tmp/ktor-micro"),
        )
        assertEquals(false, cfg.useMicrodescriptors)
        assertTrue(cfg.fetchUselessDescriptors)
        assertTrue(cfg.downloadExtraInfo)
        assertTrue(cfg.assumeReachable)
    }
}
