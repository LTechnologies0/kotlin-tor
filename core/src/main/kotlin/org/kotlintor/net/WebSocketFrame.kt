package org.kotlintor.net

import java.nio.charset.StandardCharsets
import java.security.SecureRandom

/**
 * RFC 6455 WebSocket framing — pure encode/decode for tunnels over Tor CONNECT.
 * Does not implement the HTTP Upgrade handshake (see [HttpProxyCodec] / CONNECT).
 */
object WebSocketFrame {
    const val OPCODE_CONTINUATION: Int = 0x0
    const val OPCODE_TEXT: Int = 0x1
    const val OPCODE_BINARY: Int = 0x2
    const val OPCODE_CLOSE: Int = 0x8
    const val OPCODE_PING: Int = 0x9
    const val OPCODE_PONG: Int = 0xA

    data class Frame(
        val fin: Boolean,
        val opcode: Int,
        val masked: Boolean,
        val payload: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean =
            other is Frame && fin == other.fin && opcode == other.opcode &&
                masked == other.masked && payload.contentEquals(other.payload)

        override fun hashCode(): Int =
            (((if (fin) 1 else 0) * 31 + opcode) * 31 + (if (masked) 1 else 0)) * 31 + payload.contentHashCode()
    }

    fun encode(frame: Frame, mask: Boolean = frame.masked, rng: SecureRandom = SecureRandom()): ByteArray {
        if (mask) {
            val key = ByteArray(4).also { rng.nextBytes(it) }
            val maskedPayload = ByteArray(frame.payload.size)
            for (i in frame.payload.indices) {
                maskedPayload[i] = (frame.payload[i].toInt() xor key[i % 4].toInt()).toByte()
            }
            return build(frame.fin, frame.opcode, true, key, maskedPayload)
        }
        return build(frame.fin, frame.opcode, false, null, frame.payload)
    }

    private fun build(
        fin: Boolean,
        opcode: Int,
        masked: Boolean,
        maskKey: ByteArray?,
        payload: ByteArray,
    ): ByteArray {
        val len = payload.size
        val headerSize = when {
            len < 126 -> 2
            len <= 0xffff -> 4
            else -> 10
        } + if (masked) 4 else 0
        val out = ByteArray(headerSize + len)
        out[0] = (((if (fin) 0x80 else 0) or (opcode and 0x0f))).toByte()
        var o = 1
        val maskBit = if (masked) 0x80 else 0
        when {
            len < 126 -> {
                out[o++] = (maskBit or len).toByte()
            }
            len <= 0xffff -> {
                out[o++] = (maskBit or 126).toByte()
                out[o++] = ((len ushr 8) and 0xff).toByte()
                out[o++] = (len and 0xff).toByte()
            }
            else -> {
                out[o++] = (maskBit or 127).toByte()
                // 64-bit length, high 32 zero
                for (i in 0 until 4) out[o++] = 0
                out[o++] = ((len ushr 24) and 0xff).toByte()
                out[o++] = ((len ushr 16) and 0xff).toByte()
                out[o++] = ((len ushr 8) and 0xff).toByte()
                out[o++] = (len and 0xff).toByte()
            }
        }
        if (masked && maskKey != null) {
            System.arraycopy(maskKey, 0, out, o, 4)
            o += 4
        }
        System.arraycopy(payload, 0, out, o, len)
        return out
    }

    fun tryParse(buf: ByteArray, offset: Int = 0): Pair<Frame, Int>? {
        if (buf.size - offset < 2) return null
        val b0 = buf[offset].toInt() and 0xff
        val b1 = buf[offset + 1].toInt() and 0xff
        val fin = b0 and 0x80 != 0
        val opcode = b0 and 0x0f
        val masked = b1 and 0x80 != 0
        var len = (b1 and 0x7f).toLong()
        var o = offset + 2
        when (len.toInt()) {
            126 -> {
                if (buf.size - o < 2) return null
                len = (((buf[o].toInt() and 0xff) shl 8) or (buf[o + 1].toInt() and 0xff)).toLong()
                o += 2
            }
            127 -> {
                if (buf.size - o < 8) return null
                len = 0
                for (i in 0 until 8) {
                    len = (len shl 8) or (buf[o + i].toInt() and 0xff).toLong()
                }
                o += 8
                if (len > Int.MAX_VALUE) return null
            }
        }
        val maskKey = if (masked) {
            if (buf.size - o < 4) return null
            val k = buf.copyOfRange(o, o + 4)
            o += 4
            k
        } else {
            null
        }
        if (buf.size - o < len) return null
        val raw = buf.copyOfRange(o, o + len.toInt())
        val payload = if (maskKey != null) {
            ByteArray(raw.size) { i -> (raw[i].toInt() xor maskKey[i % 4].toInt()).toByte() }
        } else {
            raw
        }
        return Frame(fin, opcode, masked, payload) to (o + len.toInt() - offset)
    }

    fun text(payload: String, mask: Boolean = true): ByteArray =
        encode(Frame(true, OPCODE_TEXT, mask, payload.toByteArray(Charsets.UTF_8)), mask)

    fun binary(payload: ByteArray, mask: Boolean = true): ByteArray =
        encode(Frame(true, OPCODE_BINARY, mask, payload), mask)
}
