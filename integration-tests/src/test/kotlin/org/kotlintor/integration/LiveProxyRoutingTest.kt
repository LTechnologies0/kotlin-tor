package org.kotlintor.integration

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.kotlintor.TorDaemon
import org.kotlintor.config.ListenSpec
import org.kotlintor.config.TorConfig
import org.kotlintor.proxy.BilingualProxyServer
import org.kotlintor.proxy.HttpConnectProxy
import org.kotlintor.proxy.Socks5Server
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.Socket
import java.nio.file.Files

/**
 * Live Tor routing through SOCKS5 + HTTP CONNECT + bilingual.
 * Enable: ./gradlew :integration-tests:test -Dkotlin.tor.liveNetwork=true
 */
class LiveProxyRoutingTest {
    @Test
    fun `socks5 and http connect over live tor`() = runBlocking {
        assumeTrue(System.getProperty("kotlin.tor.liveNetwork") == "true")
        val dir = Files.createTempDirectory("ktor-live-proxy")
        val config = TorConfig(
            dataDirectory = dir,
            socksPorts = listOf(ListenSpec("127.0.0.1", 0)),
            controlPorts = listOf(ListenSpec("127.0.0.1", 0)),
        )
        val daemon = TorDaemon(config)
        try {
            withTimeout(180_000) { daemon.start() }
            assumeTrue(daemon.client.hasCircuit, "live Tor circuit not available (PROTOCOL destroy)")
            assertTrue(daemon.client.isBootstrapped)

            val socks = Socks5Server(daemon.client, daemon.scope)
            socks.start(ListenSpec("127.0.0.1", 0))
            val http = HttpConnectProxy(daemon.client, daemon.scope)
            http.start(ListenSpec("127.0.0.1", 0))
            val bi = BilingualProxyServer(daemon.client, daemon.scope)
            bi.start(ListenSpec("127.0.0.1", 0))
            delay(200)

            val socksOk = fetchViaSocks5(socks.boundPort(), "check.torproject.org", 80)
            assertTrue(socksOk.contains("Congratulations") || socksOk.contains("torproject"), socksOk.take(200))

            val httpOk = fetchViaHttpConnect(http.boundPort(), "check.torproject.org", 80)
            assertTrue(httpOk.contains("Congratulations") || httpOk.contains("torproject"), httpOk.take(200))

            val biOk = fetchViaSocks5(bi.boundPort(), "check.torproject.org", 80)
            assertTrue(biOk.contains("Congratulations") || biOk.contains("torproject"), biOk.take(200))

            socks.stop(); http.stop(); bi.stop()
        } finally {
            daemon.stop()
        }
    }

    private fun fetchViaSocks5(proxyPort: Int, host: String, port: Int): String {
        Socket("127.0.0.1", proxyPort).use { s ->
            s.soTimeout = 60_000
            val out = s.getOutputStream()
            val inp = s.getInputStream()
            out.write(byteArrayOf(0x05, 0x01, 0x00)); out.flush()
            check(inp.read() == 0x05 && inp.read() == 0x00)
            val hb = host.toByteArray()
            out.write(byteArrayOf(0x05, 0x01, 0x00, 0x03, hb.size.toByte()) + hb +
                byteArrayOf(((port ushr 8) and 0xff).toByte(), (port and 0xff).toByte()))
            out.flush()
            check(inp.read() == 0x05 && inp.read() == 0x00)
            // drain bind addr
            inp.read(); val atyp = inp.read()
            when (atyp) {
                0x01 -> repeat(4) { inp.read() }
                0x03 -> repeat(inp.read()) { inp.read() }
                0x04 -> repeat(16) { inp.read() }
            }
            inp.read(); inp.read()
            out.write("GET / HTTP/1.0\r\nHost: $host\r\n\r\n".toByteArray()); out.flush()
            return inp.bufferedReader().readText()
        }
    }

    private fun fetchViaHttpConnect(proxyPort: Int, host: String, port: Int): String {
        Socket("127.0.0.1", proxyPort).use { s ->
            s.soTimeout = 60_000
            val w = OutputStreamWriter(s.getOutputStream())
            w.write("CONNECT $host:$port HTTP/1.1\r\nHost: $host:$port\r\n\r\n"); w.flush()
            val r = BufferedReader(InputStreamReader(s.getInputStream()))
            val status = r.readLine() ?: error("no status")
            check(status.contains("200")) { status }
            while (true) {
                val line = r.readLine() ?: break
                if (line.isEmpty()) break
            }
            w.write("GET / HTTP/1.0\r\nHost: $host\r\n\r\n"); w.flush()
            return r.readText()
        }
    }
}
