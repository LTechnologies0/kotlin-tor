package org.kotlintor.elevate

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.kotlintor.config.AutoBool
import org.kotlintor.config.TorrcParser
import org.kotlintor.dir.AuthorityCert
import org.kotlintor.dir.DetachedSignatures
import org.kotlintor.dir.DirAuthQuorum
import org.kotlintor.dir.DirAuthSigInbox
import org.kotlintor.dir.DirAuthVoteGossip
import org.kotlintor.dir.DirCache
import org.kotlintor.dir.DirCollator
import org.kotlintor.dir.MultiAuthQuorumSession
import org.kotlintor.link.ConnectionTable
import org.kotlintor.link.ConnectionType
import org.kotlintor.relay.ExitPolicy
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class DetachedSigAndOptionsElevationTest {
    @Test
    fun `typed ExitPolicyRejectPrivate IPv6Exit Padding ExitNodes BridgeAuth`() {
        val cfg = TorrcParser.parse(
            """
            DataDirectory /tmp/kt
            ExitPolicyRejectPrivate 0
            ExitPolicyRejectLocalInterfaces 0
            IPv6Exit 1
            ExitNodes ${'$'}AAAA,${'$'}BBBB
            MiddleNodes nick1
            BridgeAuthoritativeDir 1
            BridgeDistribution https
            CircuitPadding 0
            ConnectionPadding 0
            ReducedPadding 1
            AssumeReachableIPv6 1
            ClientRejectInternalAddresses 0
            ClientUseIPv4 0
            ClientUseIPv6 1
            """.trimIndent(),
            Path.of("/tmp/kt"),
        )
        assertFalse(cfg.exitPolicyRejectPrivate)
        assertFalse(cfg.exitPolicyRejectLocalInterfaces)
        assertTrue(cfg.ipv6Exit)
        assertEquals(listOf("\$AAAA", "\$BBBB"), cfg.exitNodes)
        assertEquals(listOf("nick1"), cfg.middleNodes)
        assertTrue(cfg.bridgeAuthoritativeDir)
        assertEquals("https", cfg.bridgeDistribution)
        assertFalse(cfg.circuitPadding)
        assertEquals(AutoBool.NO, cfg.connectionPadding)
        assertTrue(cfg.reducedPadding)
        assertTrue(cfg.assumeReachableIpv6)
        assertFalse(cfg.clientRejectInternalAddresses)
        assertFalse(cfg.clientUseIpv4)
        assertTrue(cfg.clientUseIpv6)
    }

    @Test
    fun `ExitPolicyRejectPrivate blocks RFC1918`() {
        val open = ExitPolicy.fromTorrcLines(listOf("accept *:*"))
            .withRejectPrivate(false)
        assertTrue(open.allows("10.0.0.1", 80))
        val closed = open.withRejectPrivate(true)
        assertFalse(closed.allows("10.0.0.1", 80))
        assertTrue(closed.allows("1.1.1.1", 80))
    }

    @Test
    fun `ConnectionTable tracks OR accepts`() {
        ConnectionTable.clear()
        val h = ConnectionTable.newOr("127.0.0.1", 9001, isClient = true)
        h.markOpen()
        assertEquals(1, ConnectionTable.countOpen())
        assertEquals(1, ConnectionTable.byType(ConnectionType.OR).size)
        h.markClosed()
        ConnectionTable.remove(h.id)
        assertEquals(0, ConnectionTable.countOpen())
    }

    @Test
    fun `N authorities POST consensus-signature until quorum`(@TempDir dir: Path) = runBlocking {
        val auths = List(3) { AuthorityCert.generate(bits = 1024) }
        val known = auths.map { it.identityFingerprint.joinToString("") { b -> "%02x".format(b) } }.toSet()
        val body = DirCollator.formatConsensusBody(emptyList())
        val detacheds = auths.map { a ->
            val sig = DetachedSignatures.signSha1Rsa(
                body,
                identityFingerprintHex = a.identityFingerprint.joinToString("") { b -> "%02x".format(b) },
                signingKeyDigestHex = a.signingKeyDigest.joinToString("") { b -> "%02x".format(b) },
                signingPrivateKey = a.signing.private,
            )
            DetachedSignatures.formatDetached(body, "2020-01-01 00:00:00", "2020-01-01 00:00:00", "2020-01-01 00:00:00", listOf(sig))
        }

        val inbox = DirAuthSigInbox()
        val received = mutableListOf<String>()
        inbox.onSig { _, doc -> received += doc }
        val cache = DirCache(dir, sigInbox = inbox)

        fun serve(): Pair<ServerSocket, Int> {
            val ss = ServerSocket()
            ss.bind(InetSocketAddress("127.0.0.1", 0))
            val ready = CountDownLatch(1)
            Executors.newSingleThreadExecutor().execute {
                ready.countDown()
                repeat(3) {
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
                            val bodyBytes = input.readNBytes(len)
                            sock.getOutputStream().write(cache.handleHttp(headers, bodyBytes))
                        } finally {
                            sock.close()
                        }
                    }
                }
                runCatching { ss.close() }
            }
            assertTrue(ready.await(3, TimeUnit.SECONDS))
            return ss to ss.localPort
        }

        val (_, port) = serve()
        for ((i, det) in detacheds.withIndex()) {
            val fp = auths[i].identityFingerprint.joinToString("") { b -> "%02x".format(b) }
            val r = DirAuthVoteGossip.postConsensusSignature("127.0.0.1", port, det, fromFp = fp)
            assertTrue(r.code in 200..299, "sig $i → ${r.code} ${r.body}")
        }
        assertEquals(3, inbox.size())
        val merged = MultiAuthQuorumSession(auths).mergeDetached(received)
        assertTrue(DirAuthQuorum.fromDetached(merged, known))
        assertTrue(merged.signatures.size >= 3)
    }
}
