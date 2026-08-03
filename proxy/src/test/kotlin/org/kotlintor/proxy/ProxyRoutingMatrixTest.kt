package org.kotlintor.proxy

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.kotlintor.config.ListenSpec
import org.kotlintor.net.ProtocolPeek
import org.kotlintor.net.runUdpGateway
import org.kotlintor.net.SocketBytePipe
import org.kotlintor.net.Socks5UdpCodec
import org.kotlintor.net.NetEndpoint
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicReference

/**
 * End-to-end routing matrix for every local proxy frontend.
 * Uses [ClearnetExitDialer] + a local echo/HTTP/FTP target (no live Tor required).
 */
class ProxyRoutingMatrixTest {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val dialer = ClearnetExitDialer()
    private lateinit var echo: ServerSocket
    private var echoPort = 0
    private val echoHits = CopyOnWriteArrayList<String>()

    @BeforeEach
    fun startEcho() {
        echo = ServerSocket(0)
        echoPort = echo.localPort
        scope.launchEcho()
    }

    @AfterEach
    fun tearDown() {
        runCatching { echo.close() }
        scope.cancel()
    }

    private fun CoroutineScope.launchEcho() = launch {
        while (true) {
            val sock = runCatching { echo.accept() }.getOrNull() ?: break
            launch {
                sock.use { s ->
                    val buf = ByteArray(4096)
                    val n = s.getInputStream().read(buf)
                    if (n > 0) {
                        val msg = buf.copyOf(n).toString(Charsets.UTF_8)
                        echoHits += msg
                        s.getOutputStream().write("ECHO:$msg".toByteArray())
                        s.getOutputStream().flush()
                    }
                }
            }
        }
    }

    private fun awaitBound(get: () -> Int): Int = runBlocking {
        withTimeout(5_000) {
            var p = get()
            while (p <= 0) {
                delay(20)
                p = get()
            }
            p
        }
    }

    @Test
    fun `socks5 connect routes to echo`() {
        val proxy = Socks5Server(dialer, scope)
        proxy.start(ListenSpec("127.0.0.1", 0))
        val port = awaitBound { proxy.boundPort() }
        try {
            Socket("127.0.0.1", port).use { s ->
                val out = s.getOutputStream()
                val inp = s.getInputStream()
                // no-auth
                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                assertEquals(0x05, inp.read())
                assertEquals(0x00, inp.read())
                val host = "127.0.0.1".toByteArray()
                out.write(
                    byteArrayOf(0x05, 0x01, 0x00, 0x03, host.size.toByte()) + host +
                        byteArrayOf(((echoPort ushr 8) and 0xff).toByte(), (echoPort and 0xff).toByte()),
                )
                out.flush()
                assertEquals(0x05, inp.read())
                assertEquals(0x00, inp.read()) // succeeded
                inp.skip(inp.available().toLong().coerceAtLeast(8)) // rest of reply
                // Some reply bytes may remain; drain fixed 8 more if needed
                val drain = ByteArray(16)
                s.soTimeout = 500
                runCatching { while (inp.available() > 0) inp.read(drain) }
                out.write("socks5-hello".toByteArray())
                out.flush()
                s.soTimeout = 5_000
                val resp = ByteArray(64)
                val n = inp.read(resp)
                assertTrue(n > 0)
                assertTrue(resp.copyOf(n).toString(Charsets.UTF_8).contains("ECHO:socks5-hello"))
            }
        } finally {
            proxy.stop()
        }
    }

    @Test
    fun `http connect routes to echo`() {
        val proxy = HttpConnectProxy(dialer, scope)
        proxy.start(ListenSpec("127.0.0.1", 0))
        val port = awaitBound { proxy.boundPort() }
        try {
            Socket("127.0.0.1", port).use { s ->
                val w = OutputStreamWriter(s.getOutputStream())
                w.write("CONNECT 127.0.0.1:$echoPort HTTP/1.1\r\nHost: 127.0.0.1:$echoPort\r\n\r\n")
                w.flush()
                val r = BufferedReader(InputStreamReader(s.getInputStream()))
                val status = r.readLine()
                assertTrue(status!!.contains("200"), status)
                while (true) {
                    val line = r.readLine() ?: break
                    if (line.isEmpty()) break
                }
                s.getOutputStream().write("http-hello".toByteArray())
                s.getOutputStream().flush()
                val buf = ByteArray(64)
                val n = s.getInputStream().read(buf)
                assertTrue(buf.copyOf(n).toString(Charsets.UTF_8).contains("ECHO:http-hello"))
            }
        } finally {
            proxy.stop()
        }
    }

    @Test
    fun `bilingual socks4 and http options`() {
        val proxy = BilingualProxyServer(dialer, scope)
        proxy.start(ListenSpec("127.0.0.1", 0))
        val port = awaitBound { proxy.boundPort() }
        try {
            // SOCKS4a
            Socket("127.0.0.1", port).use { s ->
                val host = "127.0.0.1".toByteArray()
                val req = byteArrayOf(0x04, 0x01, ((echoPort ushr 8) and 0xff).toByte(), (echoPort and 0xff).toByte(), 0, 0, 0, 1) +
                    "user".toByteArray() + byteArrayOf(0) + host + byteArrayOf(0)
                s.getOutputStream().write(req)
                s.getOutputStream().flush()
                val reply = ByteArray(8)
                assertEquals(8, s.getInputStream().read(reply))
                assertEquals(0x5a, reply[1].toInt() and 0xff) // granted (90)
                s.getOutputStream().write("s4".toByteArray())
                s.getOutputStream().flush()
                val buf = ByteArray(32)
                val n = s.getInputStream().read(buf)
                assertTrue(buf.copyOf(n).toString(Charsets.UTF_8).contains("ECHO:s4"))
            }
            // HTTP OPTIONS *
            Socket("127.0.0.1", port).use { s ->
                val w = OutputStreamWriter(s.getOutputStream())
                w.write("OPTIONS * HTTP/1.1\r\nHost: proxy\r\n\r\n")
                w.flush()
                val body = s.getInputStream().bufferedReader().readText()
                assertTrue(body.contains("200") || body.contains("Allow"), body)
            }
        } finally {
            proxy.stop()
        }
    }

    @Test
    fun `transparent prefixed dst routes`() {
        val proxy = TransparentProxy(dialer, scope, originalDst = { null })
        proxy.start(ListenSpec("127.0.0.1", 0))
        val port = awaitBound { proxy.boundPort() }
        try {
            Socket("127.0.0.1", port).use { s ->
                val hdr = byteArrayOf(127, 0, 0, 1, ((echoPort ushr 8) and 0xff).toByte(), (echoPort and 0xff).toByte())
                s.getOutputStream().write(hdr)
                s.getOutputStream().write("trans".toByteArray())
                s.getOutputStream().flush()
                val buf = ByteArray(32)
                val n = s.getInputStream().read(buf)
                assertTrue(n > 0)
                assertTrue(buf.copyOf(n).toString(Charsets.UTF_8).contains("ECHO:trans"))
            }
        } finally {
            proxy.stop()
        }
    }

    @Test
    fun `fixed tunnel peeks and routes`() {
        val peeked = AtomicReference<ProtocolPeek.Kind?>(null)
        val tunnel = FixedTorTunnel(
            dialer, scope, "127.0.0.1", echoPort,
            peekBytes = 8,
            onPeek = { peeked.set(it) },
        )
        tunnel.start(ListenSpec("127.0.0.1", 0))
        val port = awaitBound { tunnel.boundPort() }
        try {
            Socket("127.0.0.1", port).use { s ->
                s.getOutputStream().write("GET /x HTTP".toByteArray())
                s.getOutputStream().flush()
                // Need more for echo to get full message - write rest
                // actually we wrote 10 bytes; echo reads once
                val buf = ByteArray(64)
                val n = s.getInputStream().read(buf)
                assertTrue(n > 0)
                assertTrue(buf.copyOf(n).toString(Charsets.UTF_8).contains("ECHO:"))
            }
            assertEquals(ProtocolPeek.Kind.Http, peeked.get())
        } finally {
            tunnel.stop()
        }
    }

    @Test
    fun `dnsport resolves via dialer`() {
        val dns = DnsPortServer(dialer, scope)
        dns.start(ListenSpec("127.0.0.1", 0))
        val port = awaitBound { dns.boundPort() }
        try {
            val q = buildDnsQuery("localhost")
            val sock = DatagramSocket()
            sock.soTimeout = 5_000
            sock.send(DatagramPacket(q, q.size, InetAddress.getByName("127.0.0.1"), port))
            val respBuf = ByteArray(512)
            val resp = DatagramPacket(respBuf, respBuf.size)
            sock.receive(resp)
            sock.close()
            assertTrue(resp.length > 12)
            // QR bit set
            assertTrue((respBuf[2].toInt() and 0x80) != 0)
        } finally {
            dns.stop()
        }
    }

    @Test
    fun `udp associate via tor gateway routes datagram`() {
        // Gateway listens clearnet; SOCKS UDP ASSOCIATE tunnels through dialer to gateway
        val gw = UdpTorGatewayServer(scope)
        gw.start(ListenSpec("127.0.0.1", 0))
        val gwPort = awaitBound { gw.boundPort() }

        // UDP echo target
        val udpEcho = DatagramSocket(0)
        val udpEchoPort = udpEcho.localPort
        scope.launch {
            val buf = ByteArray(2048)
            while (true) {
                val p = DatagramPacket(buf, buf.size)
                runCatching { udpEcho.receive(p) }.getOrNull() ?: break
                val reply = "U:${buf.copyOf(p.length).toString(Charsets.UTF_8)}".toByteArray()
                udpEcho.send(DatagramPacket(reply, reply.size, p.socketAddress))
            }
        }

        val socks = Socks5Server(dialer, scope, udpTorGateway = "127.0.0.1" to gwPort)
        socks.start(ListenSpec("127.0.0.1", 0))
        val socksPort = awaitBound { socks.boundPort() }
        try {
            Socket("127.0.0.1", socksPort).use { ctrl ->
                val out = ctrl.getOutputStream()
                val inp = ctrl.getInputStream()
                out.write(byteArrayOf(0x05, 0x01, 0x00)); out.flush()
                assertEquals(0x05, inp.read()); assertEquals(0x00, inp.read())
                // UDP ASSOCIATE to 0.0.0.0:0
                out.write(byteArrayOf(0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0)); out.flush()
                assertEquals(0x05, inp.read())
                assertEquals(0x00, inp.read()) // ok
                inp.read(); // rsv
                assertEquals(0x01, inp.read()) // ipv4
                val ip = ByteArray(4)
                inp.read(ip)
                val pHi = inp.read(); val pLo = inp.read()
                val udpPort = (pHi shl 8) or pLo

                val clientUdp = DatagramSocket()
                val payload = "ping".toByteArray()
                val framed = Socks5UdpCodec.encode(
                    NetEndpoint.Ipv4(byteArrayOf(127, 0, 0, 1), udpEchoPort),
                    payload,
                )
                clientUdp.send(DatagramPacket(framed, framed.size, InetAddress.getByName("127.0.0.1"), udpPort))
                clientUdp.soTimeout = 5_000
                val replyPkt = DatagramPacket(ByteArray(2048), 2048)
                clientUdp.receive(replyPkt)
                val dg = Socks5UdpCodec.parse(replyPkt.data, 0, replyPkt.length)!!
                assertTrue(dg.data.toString(Charsets.UTF_8).contains("U:ping"))
                clientUdp.close()
            }
        } finally {
            socks.stop()
            gw.stop()
            udpEcho.close()
        }
    }

    @Test
    fun `onion-hosted udp gateway maps HS port and routes associate`() {
        val hosted = OnionUdpGateway.start(scope, ListenSpec("127.0.0.1", 0), onionVirtualPort = 9053)
        assertEquals(9053, hosted.onionPort.virtualPort)
        assertTrue(hosted.onionPort.target.endsWith(":${hosted.listenPort}"))

        val udpEcho = DatagramSocket(0)
        val udpEchoPort = udpEcho.localPort
        scope.launch {
            val buf = ByteArray(2048)
            while (true) {
                val p = DatagramPacket(buf, buf.size)
                runCatching { udpEcho.receive(p) }.getOrNull() ?: break
                val reply = "O:${buf.copyOf(p.length).toString(Charsets.UTF_8)}".toByteArray()
                udpEcho.send(DatagramPacket(reply, reply.size, p.socketAddress))
            }
        }

        // Dialer reaches the same TCP endpoint an onion virtport would map to.
        val socks = Socks5Server(
            dialer,
            scope,
            udpTorGateway = hosted.listenHost to hosted.listenPort,
        )
        socks.start(ListenSpec("127.0.0.1", 0))
        val socksPort = awaitBound { socks.boundPort() }
        try {
            Socket("127.0.0.1", socksPort).use { ctrl ->
                val out = ctrl.getOutputStream()
                val inp = ctrl.getInputStream()
                out.write(byteArrayOf(0x05, 0x01, 0x00)); out.flush()
                assertEquals(0x05, inp.read()); assertEquals(0x00, inp.read())
                out.write(byteArrayOf(0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0)); out.flush()
                assertEquals(0x05, inp.read())
                assertEquals(0x00, inp.read())
                inp.read()
                assertEquals(0x01, inp.read())
                inp.readNBytes(4)
                val udpPort = (inp.read() shl 8) or inp.read()
                val clientUdp = DatagramSocket()
                val framed = Socks5UdpCodec.encode(
                    NetEndpoint.Ipv4(byteArrayOf(127, 0, 0, 1), udpEchoPort),
                    "onion-udp".toByteArray(),
                )
                clientUdp.send(DatagramPacket(framed, framed.size, InetAddress.getByName("127.0.0.1"), udpPort))
                clientUdp.soTimeout = 5_000
                val replyPkt = DatagramPacket(ByteArray(2048), 2048)
                clientUdp.receive(replyPkt)
                val dg = Socks5UdpCodec.parse(replyPkt.data, 0, replyPkt.length)!!
                assertTrue(dg.data.toString(Charsets.UTF_8).contains("O:onion-udp"))
                clientUdp.close()
            }
        } finally {
            socks.stop()
            hosted.gateway.stop()
            udpEcho.close()
        }
    }

    @Test
    fun `ftp control pasv rewrite opens data via dialer`() {
        // Fake FTP server: greeting + PASV then accept data
        val ftpData = ServerSocket(0)
        val dataPort = ftpData.localPort
        val ftpCtrl = ServerSocket(0)
        val ftpCtrlPort = ftpCtrl.localPort
        scope.launch {
            val c = ftpCtrl.accept()
            val w = OutputStreamWriter(c.getOutputStream())
            val r = BufferedReader(InputStreamReader(c.getInputStream()))
            w.write("220 fake ftp\r\n"); w.flush()
            while (true) {
                val line = r.readLine() ?: break
                when {
                    line.uppercase().startsWith("PASV") -> {
                        val p1 = dataPort / 256
                        val p2 = dataPort % 256
                        w.write("227 Entering Passive Mode (127,0,0,1,$p1,$p2).\r\n"); w.flush()
                    }
                    line.uppercase().startsWith("QUIT") -> {
                        w.write("221 bye\r\n"); w.flush(); break
                    }
                    else -> {
                        w.write("200 OK\r\n"); w.flush()
                    }
                }
            }
            c.close()
        }
        scope.launch {
            val d = ftpData.accept()
            d.getOutputStream().write("FILEDATA".toByteArray())
            d.close()
        }

        val ftpProxy = FtpTorProxy(dialer, scope, "127.0.0.1", ftpCtrlPort)
        ftpProxy.start(ListenSpec("127.0.0.1", 0))
        val port = awaitBound { ftpProxy.boundPort() }
        try {
            Socket("127.0.0.1", port).use { s ->
                val r = BufferedReader(InputStreamReader(s.getInputStream()))
                val w = OutputStreamWriter(s.getOutputStream())
                assertTrue(r.readLine()!!.startsWith("220"))
                w.write("PASV\r\n"); w.flush()
                val pasv = r.readLine()!!
                assertTrue(pasv.startsWith("227"), pasv)
                // rewritten to advertiseHost 127.0.0.1 ephemeral — parse and fetch data
                val m = Regex("""\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)""").find(pasv)!!
                val g = m.groupValues
                val host = "${g[1]}.${g[2]}.${g[3]}.${g[4]}"
                val dp = g[5].toInt() * 256 + g[6].toInt()
                Socket(host, dp).use { data ->
                    val buf = ByteArray(32)
                    val n = data.getInputStream().read(buf)
                    assertEquals("FILEDATA", buf.copyOf(n).toString(Charsets.UTF_8))
                }
                w.write("QUIT\r\n"); w.flush()
            }
        } finally {
            ftpProxy.stop()
            ftpCtrl.close()
            ftpData.close()
        }
    }

    private fun buildDnsQuery(name: String): ByteArray {
        val labels = name.split('.')
        val size = 12 + labels.sumOf { 1 + it.length } + 1 + 4
        val bb = ByteBuffer.allocate(size)
        bb.putShort(0x1234) // id
        bb.putShort(0x0100) // RD
        bb.putShort(1); bb.putShort(0); bb.putShort(0); bb.putShort(0)
        for (l in labels) {
            bb.put(l.length.toByte())
            bb.put(l.toByteArray(Charsets.US_ASCII))
        }
        bb.put(0)
        bb.putShort(1); bb.putShort(1) // A IN
        return bb.array()
    }
}
