package org.kotlintor.net

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ProtocolCodecTest {
    @Test
    fun `http OPTIONS returns prop365 capabilities`() {
        val raw = "OPTIONS * HTTP/1.1\r\nHost: proxy\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
        val msg = HttpProxyCodec.parse(raw)
        assertTrue(msg is HttpProxyCodec.Message.Options)
        val resp = String(HttpProxyCodec.optionsResponse(), Charsets.ISO_8859_1)
        assertTrue(resp.contains("X-Tor-Capabilities"))
        assertTrue(resp.contains("Allow:"))
        assertTrue(resp.contains("x-tor/1.0"))
    }

    @Test
    fun `http absolute-form get`() {
        val raw = (
            "GET http://example.com/foo?x=1 HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "X-Tor-Stream-Isolation: abs1\r\n\r\n"
            ).toByteArray(Charsets.ISO_8859_1)
        val msg = HttpProxyCodec.parse(raw) as HttpProxyCodec.Message.Absolute
        assertEquals("GET", msg.method)
        assertEquals("example.com", msg.endpoint.hostString())
        assertEquals(80, msg.endpoint.port)
        assertEquals("/foo?x=1", msg.pathAndQuery)
        assertEquals("abs1", msg.isolationKey)
        val origin = String(HttpProxyCodec.toOriginForm(msg), Charsets.ISO_8859_1)
        assertTrue(origin.startsWith("GET /foo?x=1 HTTP/1.1\r\n"))
        assertTrue(!origin.contains("http://"))
    }

    @Test
    fun `https absolute-form rejected`() {
        val raw = "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
            .toByteArray(Charsets.ISO_8859_1)
        assertNull(HttpProxyCodec.parse(raw))
    }

    @Test
    fun `websocket frame roundtrip masked text`() {
        val wire = WebSocketFrame.text("hello-tor", mask = true)
        val (frame, n) = WebSocketFrame.tryParse(wire)!!
        assertEquals(n, wire.size)
        assertTrue(frame.fin)
        assertEquals(WebSocketFrame.OPCODE_TEXT, frame.opcode)
        assertEquals("hello-tor", frame.payload.toString(Charsets.UTF_8))
    }

    @Test
    fun `tls clienthello sni extract`() {
        val record = buildClientHelloWithSni("check.torproject.org")
        val peek = TlsClientHello.parse(record)!!
        assertEquals("check.torproject.org", peek.serverName)
        assertTrue(peek.cipherSuites.isNotEmpty())
        assertEquals(LocalProtocol.Tls, ProtocolDetector.detect(0x16))
    }

    @Test
    fun `protocol detector covers socks http tls`() {
        assertEquals(LocalProtocol.Socks5, ProtocolDetector.detect(0x05))
        assertEquals(LocalProtocol.Http, ProtocolDetector.detect('O'.code))
        assertEquals(LocalProtocol.Tls, ProtocolDetector.detect(0x16))
    }

    /** Minimal TLS 1.2 ClientHello record with server_name extension. */
    private fun buildClientHelloWithSni(hostname: String): ByteArray {
        val host = hostname.toByteArray(Charsets.US_ASCII)
        // SNI extension body: list_len(2) + name_type(1) + name_len(2) + name
        val sniList = ByteArray(2 + 1 + 2 + host.size)
        val nameListLen = 1 + 2 + host.size
        sniList[0] = ((nameListLen ushr 8) and 0xff).toByte()
        sniList[1] = (nameListLen and 0xff).toByte()
        sniList[2] = 0 // host_name
        sniList[3] = ((host.size ushr 8) and 0xff).toByte()
        sniList[4] = (host.size and 0xff).toByte()
        System.arraycopy(host, 0, sniList, 5, host.size)
        val extBody = ByteArray(4 + sniList.size)
        extBody[0] = 0
        extBody[1] = 0 // type server_name
        extBody[2] = ((sniList.size ushr 8) and 0xff).toByte()
        extBody[3] = (sniList.size and 0xff).toByte()
        System.arraycopy(sniList, 0, extBody, 4, sniList.size)

        val ch = ArrayList<Byte>()
        // legacy_version TLS 1.2
        ch += 0x03; ch += 0x03
        repeat(32) { ch += 0x11 } // random
        ch += 0x00 // session id len
        // cipher suites: one suite
        ch += 0x00; ch += 0x02
        ch += 0x00; ch += 0x2f // TLS_RSA_WITH_AES_128_CBC_SHA
        ch += 0x01; ch += 0x00 // compression
        // extensions
        ch += ((extBody.size ushr 8) and 0xff).toByte()
        ch += (extBody.size and 0xff).toByte()
        for (b in extBody) ch += b

        val hs = ArrayList<Byte>()
        hs += 0x01 // ClientHello
        val chLen = ch.size
        hs += ((chLen ushr 16) and 0xff).toByte()
        hs += ((chLen ushr 8) and 0xff).toByte()
        hs += (chLen and 0xff).toByte()
        hs.addAll(ch)

        val rec = ArrayList<Byte>()
        rec += 0x16 // handshake
        rec += 0x03; rec += 0x01 // record version
        rec += ((hs.size ushr 8) and 0xff).toByte()
        rec += (hs.size and 0xff).toByte()
        rec.addAll(hs)
        return rec.toByteArray()
    }
}
