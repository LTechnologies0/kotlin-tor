package org.kotlintor.net

import kotlinx.coroutines.launch
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets

/**
 * HTTP/1.1 chunked transfer coding (RFC 9112 §7.1).
 * Used to shape absolute-form proxy bodies without buffering entire content.
 */
object Http1Chunked {
    data class Chunk(val data: ByteArray, val extensions: String = "") {
        val isLast: Boolean get() = data.isEmpty()
        override fun equals(other: Any?): Boolean =
            other is Chunk && data.contentEquals(other.data) && extensions == other.extensions
        override fun hashCode(): Int = 31 * data.contentHashCode() + extensions.hashCode()
    }

    fun encodeChunk(data: ByteArray, extensions: String = ""): ByteArray {
        val hex = Integer.toHexString(data.size)
        val ext = if (extensions.isEmpty()) "" else ";$extensions"
        val head = "$hex$ext\r\n".toByteArray(StandardCharsets.US_ASCII)
        return if (data.isEmpty()) {
            head + "\r\n".toByteArray(StandardCharsets.US_ASCII)
        } else {
            head + data + "\r\n".toByteArray(StandardCharsets.US_ASCII)
        }
    }

    fun encodeLast(trailers: Map<String, String> = emptyMap()): ByteArray {
        val sb = StringBuilder("0\r\n")
        for ((k, v) in trailers) sb.append(k).append(": ").append(v).append("\r\n")
        sb.append("\r\n")
        return sb.toString().toByteArray(StandardCharsets.US_ASCII)
    }

    /**
     * Parse one chunk starting at [offset].
     * @return Pair(chunk, bytesConsumed) or null if incomplete.
     */
    fun parseChunk(buf: ByteArray, offset: Int = 0): Pair<Chunk, Int>? {
        var i = offset
        val lineEnd = indexOfCrLf(buf, i) ?: return null
        val sizeLine = buf.copyOfRange(i, lineEnd).toString(StandardCharsets.US_ASCII)
        i = lineEnd + 2
        val semi = sizeLine.indexOf(';')
        val hex = if (semi < 0) sizeLine.trim() else sizeLine.substring(0, semi).trim()
        val ext = if (semi < 0) "" else sizeLine.substring(semi + 1).trim()
        val size = hex.toIntOrNull(16) ?: return null
        if (size == 0) {
            // trailers until empty line
            val trailStart = i
            while (true) {
                val te = indexOfCrLf(buf, i) ?: return null
                if (te == i) {
                    i = te + 2
                    return Chunk(ByteArray(0), ext) to (i - offset)
                }
                i = te + 2
            }
        }
        if (buf.size - i < size + 2) return null
        val data = buf.copyOfRange(i, i + size)
        i += size
        if (buf[i] != '\r'.code.toByte() || buf[i + 1] != '\n'.code.toByte()) return null
        i += 2
        return Chunk(data, ext) to (i - offset)
    }

    private fun indexOfCrLf(buf: ByteArray, from: Int): Int? {
        var i = from
        while (i + 1 < buf.size) {
            if (buf[i] == '\r'.code.toByte() && buf[i + 1] == '\n'.code.toByte()) return i
            i++
        }
        return null
    }
}

/**
 * TLS record layer (RFC 8446 §5.1) — header only; fragment is opaque for shaping/peek.
 */
object TlsRecord {
    const val MAX_FRAGMENT: Int = 1 shl 14
    const val TYPE_CHANGE_CIPHER_SPEC: Int = 20
    const val TYPE_ALERT: Int = 21
    const val TYPE_HANDSHAKE: Int = 22
    const val TYPE_APPLICATION_DATA: Int = 23

    data class Record(val type: Int, val version: Int, val fragment: ByteArray) {
        val wireLength: Int get() = 5 + fragment.size
        override fun equals(other: Any?): Boolean =
            other is Record && type == other.type && version == other.version &&
                fragment.contentEquals(other.fragment)
        override fun hashCode(): Int = 31 * (31 * type + version) + fragment.contentHashCode()
    }

    fun parse(buf: ByteArray, offset: Int = 0): Pair<Record, Int>? {
        if (buf.size - offset < 5) return null
        val type = buf[offset].toInt() and 0xff
        val ver = ((buf[offset + 1].toInt() and 0xff) shl 8) or (buf[offset + 2].toInt() and 0xff)
        val len = ((buf[offset + 3].toInt() and 0xff) shl 8) or (buf[offset + 4].toInt() and 0xff)
        if (len > MAX_FRAGMENT + 256) return null // allow ciphertext overhead headroom
        if (buf.size - offset < 5 + len) return null
        val frag = buf.copyOfRange(offset + 5, offset + 5 + len)
        return Record(type, ver, frag) to (5 + len)
    }

    fun encode(type: Int, version: Int = 0x0303, fragment: ByteArray): ByteArray {
        require(fragment.size <= MAX_FRAGMENT)
        return byteArrayOf(
            type.toByte(),
            ((version ushr 8) and 0xff).toByte(),
            (version and 0xff).toByte(),
            ((fragment.size ushr 8) and 0xff).toByte(),
            (fragment.size and 0xff).toByte(),
        ) + fragment
    }
}

/**
 * HTTP/2 connection preface + frame header (RFC 7540 §3.5 / §4.1).
 */
object Http2Codec {
    /** Client connection preface (exact 24 octets). */
    val CLIENT_PREFACE: ByteArray =
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(StandardCharsets.US_ASCII)

    fun looksLikePreface(first: ByteArray): Boolean {
        if (first.size < CLIENT_PREFACE.size) {
            return CLIENT_PREFACE.copyOf(first.size).contentEquals(first)
        }
        return first.copyOfRange(0, CLIENT_PREFACE.size).contentEquals(CLIENT_PREFACE)
    }

    data class FrameHeader(
        val length: Int,
        val type: Int,
        val flags: Int,
        val streamId: Int,
    )

    fun parseFrameHeader(buf: ByteArray, offset: Int = 0): FrameHeader? {
        if (buf.size - offset < 9) return null
        val len = ((buf[offset].toInt() and 0xff) shl 16) or
            ((buf[offset + 1].toInt() and 0xff) shl 8) or
            (buf[offset + 2].toInt() and 0xff)
        val type = buf[offset + 3].toInt() and 0xff
        val flags = buf[offset + 4].toInt() and 0xff
        val streamId = ((buf[offset + 5].toInt() and 0x7f) shl 24) or
            ((buf[offset + 6].toInt() and 0xff) shl 16) or
            ((buf[offset + 7].toInt() and 0xff) shl 8) or
            (buf[offset + 8].toInt() and 0xff)
        return FrameHeader(len, type, flags, streamId)
    }

    fun encodeFrameHeader(length: Int, type: Int, flags: Int, streamId: Int): ByteArray {
        require(length in 0..0xFFFFFF)
        require(streamId >= 0)
        return byteArrayOf(
            ((length ushr 16) and 0xff).toByte(),
            ((length ushr 8) and 0xff).toByte(),
            (length and 0xff).toByte(),
            type.toByte(),
            flags.toByte(),
            ((streamId ushr 24) and 0x7f).toByte(),
            ((streamId ushr 16) and 0xff).toByte(),
            ((streamId ushr 8) and 0xff).toByte(),
            (streamId and 0xff).toByte(),
        )
    }
}

/**
 * RESP2 (Redis Serialization Protocol) — enough to shape/tunnel Redis over Tor TCP.
 */
object RedisResp {
    sealed class Value {
        data class SimpleString(val s: String) : Value()
        data class Error(val s: String) : Value()
        data class Integer(val n: Long) : Value()
        data class BulkString(val bytes: ByteArray?) : Value() {
            override fun equals(other: Any?): Boolean =
                other is BulkString && (
                    (bytes == null && other.bytes == null) ||
                        (bytes != null && other.bytes != null && bytes.contentEquals(other.bytes))
                    )
            override fun hashCode(): Int = bytes?.contentHashCode() ?: 0
        }
        data class Array(val items: List<Value>?) : Value()
    }

    fun encode(v: Value): ByteArray = when (v) {
        is Value.SimpleString -> "+${v.s}\r\n".toByteArray(StandardCharsets.UTF_8)
        is Value.Error -> "-${v.s}\r\n".toByteArray(StandardCharsets.UTF_8)
        is Value.Integer -> ":${v.n}\r\n".toByteArray(StandardCharsets.UTF_8)
        is Value.BulkString -> {
            if (v.bytes == null) "\$-1\r\n".toByteArray(StandardCharsets.US_ASCII)
            else {
                val head = "\$${v.bytes.size}\r\n".toByteArray(StandardCharsets.US_ASCII)
                head + v.bytes + "\r\n".toByteArray(StandardCharsets.US_ASCII)
            }
        }
        is Value.Array -> {
            if (v.items == null) "*-1\r\n".toByteArray(StandardCharsets.US_ASCII)
            else {
                val head = "*${v.items.size}\r\n".toByteArray(StandardCharsets.US_ASCII)
                v.items.fold(head) { acc, item -> acc + encode(item) }
            }
        }
    }

    fun encodeCommand(parts: List<String>): ByteArray =
        encode(Value.Array(parts.map { Value.BulkString(it.toByteArray(StandardCharsets.UTF_8)) }))

    fun parse(buf: ByteArray, offset: Int = 0): Pair<Value, Int>? {
        if (offset >= buf.size) return null
        return when (buf[offset].toInt().toChar()) {
            '+' -> parseLine(buf, offset + 1)?.let { (s, n) -> Value.SimpleString(s) to (1 + n) }
            '-' -> parseLine(buf, offset + 1)?.let { (s, n) -> Value.Error(s) to (1 + n) }
            ':' -> parseLine(buf, offset + 1)?.let { (s, n) ->
                Value.Integer(s.toLongOrNull() ?: return null) to (1 + n)
            }
            '$' -> {
                val (lenStr, n) = parseLine(buf, offset + 1) ?: return null
                val len = lenStr.toIntOrNull() ?: return null
                if (len < 0) return Value.BulkString(null) to (1 + n)
                val start = offset + 1 + n
                if (buf.size - start < len + 2) return null
                val bytes = buf.copyOfRange(start, start + len)
                Value.BulkString(bytes) to (1 + n + len + 2)
            }
            '*' -> {
                val (lenStr, n) = parseLine(buf, offset + 1) ?: return null
                val len = lenStr.toIntOrNull() ?: return null
                if (len < 0) return Value.Array(null) to (1 + n)
                var o = offset + 1 + n
                val items = ArrayList<Value>(len)
                repeat(len) {
                    val (v, used) = parse(buf, o) ?: return null
                    items += v
                    o += used
                }
                Value.Array(items) to (o - offset)
            }
            else -> null
        }
    }

    fun looksLike(first: ByteArray): Boolean {
        if (first.isEmpty()) return false
        val c = first[0].toInt().toChar()
        return c == '*' || c == '$' || c == '+' || c == '-' || c == ':'
    }

    private fun parseLine(buf: ByteArray, offset: Int): Pair<String, Int>? {
        var i = offset
        while (i + 1 < buf.size) {
            if (buf[i] == '\r'.code.toByte() && buf[i + 1] == '\n'.code.toByte()) {
                val s = buf.copyOfRange(offset, i).toString(Charsets.UTF_8)
                return s to (i - offset + 2)
            }
            i++
        }
        return null
    }
}

/**
 * Length-prefixed UDP datagram encapsulation over a Tor TCP stream.
 *
 * Wire: `u16be total | SOCKS5-UDP-header-without-payload | payload`
 * where total = header+payload length (max 65535).
 *
 * Bridges SOCKS5 UDP ASSOCIATE → Tor until native Tor UDP exits exist:
 * client encodes datagrams onto a Tor CONNECT to [gateway]; gateway unpacks
 * and speaks clearnet UDP (or another hop).
 */
object UdpOverTcpFrame {
    fun encode(endpoint: NetEndpoint, payload: ByteArray): ByteArray {
        val body = Socks5UdpCodec.encode(endpoint, payload)
        require(body.size <= 0xffff)
        return byteArrayOf(
            ((body.size ushr 8) and 0xff).toByte(),
            (body.size and 0xff).toByte(),
        ) + body
    }

    fun parse(buf: ByteArray, offset: Int = 0): Pair<Socks5UdpCodec.Datagram, Int>? {
        if (buf.size - offset < 2) return null
        val total = ((buf[offset].toInt() and 0xff) shl 8) or (buf[offset + 1].toInt() and 0xff)
        if (buf.size - offset < 2 + total) return null
        val dg = Socks5UdpCodec.parse(buf, offset + 2, total) ?: return null
        return dg to (2 + total)
    }
}

/**
 * SOCKS5 UDP ASSOCIATE bridged over a Tor TCP stream to a UDP gateway.
 * Local UDP ↔ [UdpOverTcpFrame] ↔ [torPipe] (Tor CONNECT to gateway).
 */
suspend fun socks5UdpAssociateViaTor(
    control: BytePipe,
    clientHint: NetEndpoint,
    torPipe: BytePipe,
): Unit = kotlinx.coroutines.coroutineScope {
    val udp = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        DatagramSocket(0)
    }
    val bindEp = NetEndpoint.Ipv4(byteArrayOf(127, 0, 0, 1), udp.localPort)
    control.write(Socks5Codec.encodeReply(Socks5Codec.Reply(Socks5Reply.Succeeded, bindEp)))
    val expected = when (clientHint) {
        is NetEndpoint.Ipv4 ->
            if (clientHint.octets.contentEquals(byteArrayOf(0, 0, 0, 0))) null
            else InetAddress.getByAddress(clientHint.octets)
        else -> null
    }
    val clientAddr = java.util.concurrent.atomic.AtomicReference<java.net.SocketAddress?>(null)
    val up = launch(kotlinx.coroutines.Dispatchers.IO) {
        val buf = ByteArray(65535)
        while (!control.isClosed() && !torPipe.isClosed()) {
            udp.soTimeout = 500
            val packet = DatagramPacket(buf, buf.size)
            try {
                udp.receive(packet)
            } catch (_: java.net.SocketTimeoutException) {
                continue
            } catch (_: Exception) {
                break
            }
            if (expected != null && packet.address != expected) continue
            clientAddr.set(packet.socketAddress)
            val dg = Socks5UdpCodec.parse(packet.data, 0, packet.length) ?: continue
            torPipe.write(UdpOverTcpFrame.encode(dg.endpoint, dg.data))
        }
    }
    val down = launch(kotlinx.coroutines.Dispatchers.IO) {
        val acc = ArrayList<Byte>()
        val tmp = ByteArray(8192)
        while (!control.isClosed() && !torPipe.isClosed()) {
            val n = torPipe.read(tmp)
            if (n < 0) break
            if (n == 0) continue
            for (i in 0 until n) acc.add(tmp[i])
            while (true) {
                val arr = acc.toByteArray()
                val parsed = UdpOverTcpFrame.parse(arr) ?: break
                val (dg, used) = parsed
                repeat(used) { acc.removeAt(0) }
                val dest = clientAddr.get() ?: continue
                val wrapped = Socks5UdpCodec.encode(dg.endpoint, dg.data)
                udp.send(DatagramPacket(wrapped, wrapped.size, dest))
            }
        }
    }
    try {
        while (!control.isClosed()) {
            kotlinx.coroutines.delay(200)
        }
    } finally {
        up.cancel()
        down.cancel()
        runCatching { udp.close() }
        runCatching { torPipe.close() }
    }
}

/** Clearnet UDP gateway: unpack [UdpOverTcpFrame] from TCP, send/recv UDP, re-frame. */
suspend fun runUdpGateway(tcp: BytePipe): Unit = kotlinx.coroutines.coroutineScope {
    val udp = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) { DatagramSocket() }
    val up = launch(kotlinx.coroutines.Dispatchers.IO) {
        val acc = ArrayList<Byte>()
        val tmp = ByteArray(8192)
        while (!tcp.isClosed()) {
            val n = tcp.read(tmp)
            if (n < 0) break
            for (i in 0 until n) acc.add(tmp[i])
            while (true) {
                val arr = acc.toByteArray()
                val parsed = UdpOverTcpFrame.parse(arr) ?: break
                val (dg, used) = parsed
                repeat(used) { acc.removeAt(0) }
                val target = when (val e = dg.endpoint) {
                    is NetEndpoint.Ipv4 -> InetSocketAddress(InetAddress.getByAddress(e.octets), e.port)
                    is NetEndpoint.Ipv6 -> InetSocketAddress(InetAddress.getByAddress(e.octets), e.port)
                    is NetEndpoint.Domain -> InetSocketAddress(e.name, e.port)
                }
                udp.send(DatagramPacket(dg.data, dg.data.size, target))
                val replyBuf = ByteArray(65535)
                val reply = DatagramPacket(replyBuf, replyBuf.size)
                udp.soTimeout = 3_000
                try {
                    udp.receive(reply)
                    val addr = reply.address.address
                    val ep = if (addr.size == 4) NetEndpoint.Ipv4(addr, reply.port)
                    else NetEndpoint.Ipv6(addr, reply.port)
                    tcp.write(UdpOverTcpFrame.encode(ep, replyBuf.copyOf(reply.length)))
                } catch (_: Exception) {
                    // drop
                }
            }
        }
    }
    try {
        up.join()
    } finally {
        up.cancel()
        runCatching { udp.close() }
    }
}
