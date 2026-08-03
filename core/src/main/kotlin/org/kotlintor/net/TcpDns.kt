package org.kotlintor.net

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * RFC 793 TCP header parse/build (20-byte base, no options required).
 * Checksum filled by [org.kotlintor.net.stack.TcpSegment] for the userspace stack.
 */
object TcpHeader {
    data class Segment(
        val srcPort: Int,
        val dstPort: Int,
        val seq: Long,
        val ack: Long,
        val dataOffsetWords: Int,
        val flags: Int,
        val window: Int,
        val checksum: Int,
        val urgent: Int,
        val payload: ByteArray,
    ) {
        val syn: Boolean get() = flags and 0x02 != 0
        val ackFlag: Boolean get() = flags and 0x10 != 0
        val fin: Boolean get() = flags and 0x01 != 0
        val rst: Boolean get() = flags and 0x04 != 0
        val psh: Boolean get() = flags and 0x08 != 0

        override fun equals(other: Any?): Boolean =
            other is Segment && srcPort == other.srcPort && dstPort == other.dstPort &&
                seq == other.seq && ack == other.ack && flags == other.flags &&
                payload.contentEquals(other.payload)

        override fun hashCode(): Int =
            (((srcPort * 31 + dstPort) * 31 + seq.toInt()) * 31 + flags) * 31 + payload.contentHashCode()
    }

    fun parse(packet: ByteArray, offset: Int = 0, length: Int = packet.size - offset): Segment? {
        if (length < 20) return null
        val bb = ByteBuffer.wrap(packet, offset, length).order(ByteOrder.BIG_ENDIAN)
        val src = bb.short.toInt() and 0xffff
        val dst = bb.short.toInt() and 0xffff
        val seq = bb.int.toLong() and 0xffffffffL
        val ack = bb.int.toLong() and 0xffffffffL
        val offFlags = bb.short.toInt() and 0xffff
        val dataOff = (offFlags ushr 12) and 0x0f
        val flags = offFlags and 0x01ff
        val window = bb.short.toInt() and 0xffff
        val csum = bb.short.toInt() and 0xffff
        val urg = bb.short.toInt() and 0xffff
        val hdrBytes = dataOff * 4
        if (hdrBytes < 20 || length < hdrBytes) return null
        val payload = packet.copyOfRange(offset + hdrBytes, offset + length)
        return Segment(src, dst, seq, ack, dataOff, flags, window, csum, urg, payload)
    }

    fun build(
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        window: Int = 65535,
        payload: ByteArray = ByteArray(0),
    ): ByteArray {
        val bb = ByteBuffer.allocate(20 + payload.size).order(ByteOrder.BIG_ENDIAN)
        bb.putShort(srcPort.toShort())
        bb.putShort(dstPort.toShort())
        bb.putInt(seq.toInt())
        bb.putInt(ack.toInt())
        val offFlags = (5 shl 12) or (flags and 0x1ff)
        bb.putShort(offFlags.toShort())
        bb.putShort(window.toShort())
        bb.putShort(0) // checksum filled by stack / later
        bb.putShort(0)
        bb.put(payload)
        return bb.array()
    }
}

/**
 * RFC 1035 §4.2.2 — DNS over TCP: 2-byte BE length prefix + message.
 */
object DnsTcpFraming {
    fun encode(message: ByteArray): ByteArray {
        require(message.size <= 65535)
        return byteArrayOf(
            ((message.size ushr 8) and 0xff).toByte(),
            (message.size and 0xff).toByte(),
        ) + message
    }

    fun tryDecode(buf: ByteArray, offset: Int = 0): Pair<ByteArray, Int>? {
        if (buf.size - offset < 2) return null
        val len = ((buf[offset].toInt() and 0xff) shl 8) or (buf[offset + 1].toInt() and 0xff)
        if (buf.size - offset < 2 + len) return null
        return buf.copyOfRange(offset + 2, offset + 2 + len) to (2 + len)
    }
}
