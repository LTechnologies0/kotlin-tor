package org.kotlintor.net.stack

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.net.MemoryBytePipe
import org.kotlintor.net.SafeSocksPolicy
import org.kotlintor.net.TcpHeader

class FakeIpDnsAndOnionTunnelTest {
    private fun withStackScope(block: suspend CoroutineScope.() -> Unit) = runBlocking {
        val job = SupervisorJob()
        val scope = CoroutineScope(job + Dispatchers.Default)
        try {
            scope.block()
        } finally {
            job.cancel()
        }
    }

    @Test
    fun `fake-IP cookies v4 reverse and TTL cache`() {
        val cookies = FakeIpDnsCookies()
        val ip = cookies.makeForV4("example.com")
        assertTrue(ip.startsWith("10."))
        assertEquals("example.com", cookies.reverse(ip))
        assertTrue(cookies.isCookieIp(ip))
        assertTrue(SafeSocksPolicy.allows(ip, safeSocks = true, allowIpLiterals = true))
        assertFalse(SafeSocksPolicy.allows(ip, safeSocks = true, allowIpLiterals = false))
    }

    @Test
    fun `trailing dot stripped`() {
        val cookies = FakeIpDnsCookies()
        val ip = cookies.makeForV4("Example.COM.")
        assertEquals("example.com", cookies.reverse(ip))
    }

    @Test
    fun `DNS A reply TTL 60 via TunFakeDns`() {
        val dns = TunFakeDns()
        val q = buildDnsQuery("www.example.com", TunFakeDns.QTYPE_A)
        val resp = dns.handleQuery(q)!!
        assertTrue(resp.size > 12)
        val ttlOff = findFirstAnswerTtlOffset(resp)
        assertNotNull(ttlOff)
        val ttl = ((resp[ttlOff!!].toInt() and 0xff) shl 24) or
            ((resp[ttlOff + 1].toInt() and 0xff) shl 16) or
            ((resp[ttlOff + 2].toInt() and 0xff) shl 8) or
            (resp[ttlOff + 3].toInt() and 0xff)
        assertEquals(60, ttl)
        val a = resp.copyOfRange(resp.size - 4, resp.size)
        val ipStr = a.joinToString(".") { (it.toInt() and 0xff).toString() }
        assertEquals("www.example.com", dns.cookies.reverse(ipStr))
    }

    @Test
    fun `TUN UDP DNS answered via stack sendUdp`() = withStackScope {
        val out = Channel<ByteArray>(Channel.BUFFERED)
        val dns = TunFakeDns()
        lateinit var stack: TunIpStack
        stack = TunIpStack(
            scope = this,
            emit = { out.send(it) },
            openTcp = { _, _ -> MemoryBytePipe() },
            onUdp = { srcIp, srcPort, dstIp, dstPort, payload ->
                if (dstPort != 53) return@TunIpStack
                val reply = dns.handleQuery(payload) ?: return@TunIpStack
                stack.sendUdp(dstIp, dstPort, srcIp, srcPort, reply)
            },
        )
        val client = Ipv4Packet.parseAddress("10.8.0.2")
        val resolver = Ipv4Packet.parseAddress(FakeIpDnsCookies.FAKE_RESOLVER_V4)
        val q = buildDnsQuery("onion.test", TunFakeDns.QTYPE_A)
        val udp = UdpDatagram.build(client, resolver, 40000, 53, q)
        stack.inject(Ipv4Packet.build(client, resolver, Ipv4Packet.PROTO_UDP, udp))
        val replyIp = withTimeout(2_000) { out.receive() }
        val ip = Ipv4Packet.parse(replyIp)!!
        assertEquals(FakeIpDnsCookies.FAKE_RESOLVER_V4, ip.srcString())
        assertEquals("10.8.0.2", ip.dstString())
        val dg = UdpDatagram.parse(ip.payload)!!
        assertEquals(53, dg.srcPort)
        assertTrue(dg.payload.size > 12)
        out.close()
    }

    @Test
    fun `non-DNS UDP is dropped`() = withStackScope {
        val out = Channel<ByteArray>(Channel.BUFFERED)
        var udpHits = 0
        val stack = TunIpStack(
            scope = this,
            emit = { out.send(it) },
            openTcp = { _, _ -> MemoryBytePipe() },
            onUdp = { _, _, _, dstPort, _ ->
                udpHits++
                if (dstPort != 53) return@TunIpStack
            },
        )
        val client = Ipv4Packet.parseAddress("10.8.0.2")
        val dst = Ipv4Packet.parseAddress("1.2.3.4")
        val udp = UdpDatagram.build(client, dst, 40000, 443, byteArrayOf(1, 2, 3))
        stack.inject(Ipv4Packet.build(client, dst, Ipv4Packet.PROTO_UDP, udp))
        delay(50)
        assertEquals(1, udpHits)
        assertTrue(out.isEmpty)
        out.close()
    }

    @Test
    fun `tcp syn bridges via cookie hostname`() = withStackScope {
        val out = Channel<ByteArray>(Channel.BUFFERED)
        val cookies = FakeIpDnsCookies()
        val cookieIp = cookies.makeForV4("example.org")
        val remote = MemoryBytePipe()
        val stack = TunIpStack(
            scope = this,
            emit = { out.send(it) },
            openTcp = { host, port ->
                val resolved = cookies.reverse(host) ?: host
                assertEquals("example.org", resolved)
                assertEquals(443, port)
                remote
            },
        )
        val client = Ipv4Packet.parseAddress("10.8.0.2")
        val server = Ipv4Packet.parseAddress(cookieIp)
        val syn = TcpSegment.build(
            client, server, 40000, 443,
            seq = 1000L, ack = 0L, flags = TcpSegment.FLAG_SYN,
        )
        stack.inject(Ipv4Packet.build(client, server, Ipv4Packet.PROTO_TCP, syn))
        val synAckPkt = withTimeout(2_000) { out.receive() }
        val synAck = TcpHeader.parse(Ipv4Packet.parse(synAckPkt)!!.payload)!!
        assertTrue(synAck.syn && synAck.ackFlag)
        remote.close()
        delay(50)
        out.close()
    }

    @Test
    fun `memory tun pumps icmp through OnionTunnel-style bridge`() = withStackScope {
        val tun = MemoryTun()
        val bridge = TunTorBridge(
            scope = this,
            io = tun,
            openTcp = { _, _ -> MemoryBytePipe() },
            onUdp = { _, _, _, _, _ -> },
        )
        bridge.start()
        val src = Ipv4Packet.parseAddress("10.8.0.2")
        val dst = Ipv4Packet.parseAddress("8.8.8.8")
        val echo = ByteArray(8)
        echo[0] = IcmpEcho.TYPE_ECHO_REQUEST.toByte()
        val csum = InternetChecksum.compute(echo)
        echo[2] = ((csum ushr 8) and 0xff).toByte()
        echo[3] = (csum and 0xff).toByte()
        tun.injectFromDevice(Ipv4Packet.build(src, dst, Ipv4Packet.PROTO_ICMP, echo))
        val out = withTimeout(2_000) { tun.takeEmitted() }
        assertEquals(IcmpEcho.TYPE_ECHO_REPLY, IcmpEcho.parse(Ipv4Packet.parse(out)!!.payload)!!.type)
        bridge.stop()
    }

    @Test
    fun `fake-IP cookie map respects maxEntries`() {
        val cookies = FakeIpDnsCookies(maxEntries = 4)
        repeat(8) { i -> cookies.makeForV4("host$i.example") }
        assertTrue(cookies.sizeV4() <= 4)
    }

    private fun buildDnsQuery(name: String, qtype: Int): ByteArray {
        val labels = name.split('.')
        val size = 12 + labels.sumOf { 1 + it.length } + 1 + 4
        val buf = ByteArray(size)
        buf[0] = 0x12; buf[1] = 0x34
        buf[2] = 0x01; buf[3] = 0x00
        buf[4] = 0x00; buf[5] = 0x01
        var i = 12
        for (lab in labels) {
            buf[i++] = lab.length.toByte()
            for (c in lab) buf[i++] = c.code.toByte()
        }
        buf[i++] = 0
        buf[i++] = ((qtype ushr 8) and 0xff).toByte()
        buf[i++] = (qtype and 0xff).toByte()
        buf[i++] = 0x00; buf[i] = 0x01
        return buf
    }

    private fun findFirstAnswerTtlOffset(resp: ByteArray): Int? {
        var i = 12
        while (i < resp.size && resp[i] != 0.toByte()) {
            i += 1 + (resp[i].toInt() and 0xff)
        }
        i += 5
        if (i + 10 >= resp.size) return null
        return i + 2 + 2 + 2
    }
}
