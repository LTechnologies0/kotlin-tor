package org.kotlintor.net

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class FramingProtocolsTest {
    @Test
    fun `http1 chunked roundtrip`() {
        val body = "Hello".toByteArray()
        val enc = Http1Chunked.encodeChunk(body) + Http1Chunked.encodeLast()
        val (c1, n1) = Http1Chunked.parseChunk(enc)!!
        assertEquals("Hello", c1.data.toString(Charsets.US_ASCII))
        val (c2, _) = Http1Chunked.parseChunk(enc, n1)!!
        assertTrue(c2.isLast)
    }

    @Test
    fun `tls record roundtrip`() {
        val frag = byteArrayOf(1, 2, 3, 4)
        val wire = TlsRecord.encode(TlsRecord.TYPE_HANDSHAKE, 0x0303, frag)
        val (rec, n) = TlsRecord.parse(wire)!!
        assertEquals(TlsRecord.TYPE_HANDSHAKE, rec.type)
        assertEquals(0x0303, rec.version)
        assertTrue(rec.fragment.contentEquals(frag))
        assertEquals(wire.size, n)
    }

    @Test
    fun `http2 preface and frame header`() {
        assertTrue(Http2Codec.looksLikePreface(Http2Codec.CLIENT_PREFACE))
        val hdr = Http2Codec.encodeFrameHeader(8, 0x4, 0, 0) // SETTINGS
        val p = Http2Codec.parseFrameHeader(hdr)!!
        assertEquals(8, p.length)
        assertEquals(0x4, p.type)
        assertEquals(0, p.streamId)
    }

    @Test
    fun `redis resp command`() {
        val wire = RedisResp.encodeCommand(listOf("SET", "k", "v"))
        val (v, n) = RedisResp.parse(wire)!!
        assertEquals(wire.size, n)
        val arr = v as RedisResp.Value.Array
        assertEquals(3, arr.items!!.size)
        assertEquals(
            "SET",
            (arr.items[0] as RedisResp.Value.BulkString).bytes!!.toString(Charsets.UTF_8),
        )
        assertTrue(RedisResp.looksLike(wire))
        assertEquals(ProtocolPeek.Kind.Redis, ProtocolPeek.classify(wire.copyOf(8)))
        assertEquals(ProtocolPeek.Kind.Http2, ProtocolPeek.classify(Http2Codec.CLIENT_PREFACE))
    }

    @Test
    fun `udp over tcp frame`() {
        val ep = NetEndpoint.Domain("example.com", 53)
        val payload = byteArrayOf(0x12, 0x34)
        val frame = UdpOverTcpFrame.encode(ep, payload)
        val (dg, used) = UdpOverTcpFrame.parse(frame)!!
        assertEquals(frame.size, used)
        assertEquals("example.com", (dg.endpoint as NetEndpoint.Domain).name)
        assertEquals(53, dg.endpoint.port)
        assertTrue(dg.data.contentEquals(payload))
    }

    @Test
    fun `postgres startup`() {
        val wire = PostgresStartup.encode("alice", "db1")
        val (msg, n) = PostgresStartup.parse(wire)!!
        assertEquals(wire.size, n)
        assertEquals(PostgresStartup.PROTOCOL_3_0, msg.protocol)
        assertEquals("alice", msg.params["user"])
        assertEquals("db1", msg.params["database"])
        assertEquals(ProtocolPeek.Kind.Postgres, ProtocolPeek.classify(wire))
    }
}
