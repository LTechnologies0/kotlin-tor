package org.kotlintor.net

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.Base64

class NetCodecTest {
    @Test
    fun `socks5 method offer and select RFC1928`() {
        val offer = byteArrayOf(0x05, 0x02, 0x00, 0x02)
        val (parsed, consumed) = Socks5Codec.parseMethodOffer(offer)!!
        assertEquals(4, consumed)
        assertEquals(listOf(0, 2), parsed.methods)
        assertEquals(0x02, Socks5Codec.selectMethod(parsed))
        assertArrayEquals(byteArrayOf(0x05, 0x02), Socks5Codec.encodeMethodSelect(0x02))
    }

    @Test
    fun `socks5 connect domain request`() {
        // VER CMD RSV ATYP LEN example.com PORT 443
        val name = "example.com".toByteArray()
        val req = byteArrayOf(0x05, 0x01, 0x00, 0x03, name.size.toByte()) + name +
            byteArrayOf(0x01, 0xbb.toByte())
        val (parsed, _) = Socks5Codec.parseRequest(req)!!
        assertEquals(Socks5Command.Connect, parsed.command)
        assertEquals("example.com", (parsed.endpoint as NetEndpoint.Domain).name)
        assertEquals(443, parsed.endpoint.port)
    }

    @Test
    fun `socks5 reply encode`() {
        val bytes = Socks5Codec.encodeReply(Socks5Codec.Reply(Socks5Reply.Succeeded))
        assertEquals(0x05, bytes[0].toInt() and 0xff)
        assertEquals(0x00, bytes[1].toInt() and 0xff)
        assertEquals(0x01, bytes[3].toInt() and 0xff) // IPv4 bind
    }

    @Test
    fun `socks4a domain request`() {
        val domain = "onion.test"
        val user = "alice"
        val body = byteArrayOf(0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1) +
            user.toByteArray() + byteArrayOf(0) +
            domain.toByteArray() + byteArrayOf(0)
        val (req, _) = Socks4Codec.parseRequest(body)!!
        assertEquals("onion.test", (req.endpoint as NetEndpoint.Domain).name)
        assertEquals(80, req.endpoint.port)
        assertEquals("alice", req.userId)
    }

    @Test
    fun `http connect with prop365 headers`() {
        val auth = Base64.getEncoder().encodeToString("x-tor:secret".toByteArray())
        val raw = (
            "CONNECT example.com:443 HTTP/1.1\r\n" +
                "Host: example.com:443\r\n" +
                "Proxy-Authorization: Basic $auth\r\n" +
                "X-Tor-Stream-Isolation: myiso\r\n" +
                "X-Tor-Family-Preference: ipv6-preferred\r\n" +
                "\r\n"
            ).toByteArray(Charsets.ISO_8859_1)
        val req = HttpConnectCodec.parseRequest(raw)!!
        assertEquals("example.com", req.endpoint.hostString())
        assertEquals(443, req.endpoint.port)
        assertEquals("myiso", req.isolationKey) // X-Tor wins over Proxy-Authorization
        assertEquals(FamilyPreference.Ipv6Preferred, req.familyPreference)
    }

    @Test
    fun `protocol detector bilingual`() {
        assertEquals(LocalProtocol.Socks5, ProtocolDetector.detect(0x05))
        assertEquals(LocalProtocol.Socks4, ProtocolDetector.detect(0x04))
        assertEquals(LocalProtocol.Http, ProtocolDetector.detect('C'.code))
    }

    @Test
    fun `tcp header parse roundtrip`() {
        val built = TcpHeader.build(1234, 443, 1, 0, flags = 0x02, payload = byteArrayOf(1, 2, 3))
        val seg = TcpHeader.parse(built)!!
        assertEquals(1234, seg.srcPort)
        assertEquals(443, seg.dstPort)
        assertTrue(seg.syn)
        assertArrayEquals(byteArrayOf(1, 2, 3), seg.payload)
    }

    @Test
    fun `dns tcp framing`() {
        val msg = byteArrayOf(0x12, 0x34, 0x01, 0x00)
        val framed = DnsTcpFraming.encode(msg)
        val (decoded, n) = DnsTcpFraming.tryDecode(framed)!!
        assertEquals(6, n)
        assertArrayEquals(msg, decoded)
    }

    @Test
    fun `negotiate socks5 over buffered pipe`() = runBlocking {
        val responses = ArrayList<ByteArray>()
        val sink = object : BytePipe {
            override val bytesRead = 0L
            override val bytesWritten = 0L
            override fun isClosed() = false
            override suspend fun close() = Unit
            override suspend fun read(dst: ByteArray, offset: Int, length: Int) = -1
            override suspend fun write(src: ByteArray, offset: Int, length: Int) {
                responses += src.copyOfRange(offset, offset + length)
            }
        }
        val handshake = byteArrayOf(
            0x05, 0x01, 0x00,
            0x05, 0x01, 0x00, 0x03, 0x0b,
        ) + "example.com".toByteArray() + byteArrayOf(0x01, 0xbb.toByte())
        val buf = BufferedBytePipe(sink)
        buf.pushFront(handshake)
        val outcome = negotiateSocks5(buf, preferUserPass = false)
        assertNotNull(outcome)
        val route = (outcome as Socks5Outcome.Connect).route
        assertEquals("example.com", route.endpoint.hostString())
        assertEquals(443, route.endpoint.port)
        assertTrue(responses.isNotEmpty())
        assertEquals(0x05, responses[0][0].toInt() and 0xff) // method select
    }

    @Test
    fun `socks5 udp header roundtrip`() {
        val ep = NetEndpoint.Domain("dns.example", 53)
        val payload = byteArrayOf(1, 2, 3, 4)
        val wire = Socks5UdpCodec.encode(ep, payload)
        val parsed = Socks5UdpCodec.parse(wire)!!
        assertEquals("dns.example", parsed.endpoint.hostString())
        assertEquals(53, parsed.endpoint.port)
        assertArrayEquals(payload, parsed.data)
    }
}
