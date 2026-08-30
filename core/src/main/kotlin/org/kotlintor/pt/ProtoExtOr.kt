package org.kotlintor.pt

import org.kotlintor.util.readU16be
import org.kotlintor.util.u16be

/**
 * Extended ORPort binary framing (C Tor `proto_ext_or.c`).
 *
 * Inventory: `L1:core/proto/proto_ext_or.c`
 *
 * Wire: 2-byte command + 2-byte body length + body.
 * Text-line ExtORPort handshake lives in [ExtOrPortServer].
 */
object ProtoExtOr {
    const val HEADER_SIZE: Int = 4

    data class ExtOrCmd(val cmd: Int, val body: ByteArray) {
        override fun equals(other: Any?): Boolean =
            other is ExtOrCmd && cmd == other.cmd && body.contentEquals(other.body)

        override fun hashCode(): Int = cmd xor body.contentHashCode()
    }

    fun encode(cmd: Int, body: ByteArray = ByteArray(0)): ByteArray =
        u16be(cmd and 0xffff) + u16be(body.size and 0xffff) + body

    /**
     * C Tor `fetch_ext_or_command_from_buf`.
     * @return null if incomplete; [ExtOrCmd] if a full frame is present (consumed from front).
     */
    fun fetchFromBuffer(buf: ByteArray): Pair<ExtOrCmd, ByteArray>? {
        if (buf.size < HEADER_SIZE) return null
        val cmd = readU16be(buf, 0)
        val len = readU16be(buf, 2)
        if (buf.size < HEADER_SIZE + len) return null
        val body = buf.copyOfRange(HEADER_SIZE, HEADER_SIZE + len)
        val rest = buf.copyOfRange(HEADER_SIZE + len, buf.size)
        return ExtOrCmd(cmd, body) to rest
    }

    fun tryParse(buf: ByteArray): ExtOrCmd? = fetchFromBuffer(buf)?.first
}
