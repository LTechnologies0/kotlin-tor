package org.kotlintor.net.stack

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** UDP datagram (RFC 768) with IPv4 pseudo-header checksum. */
object UdpDatagram {
    data class Datagram(
        val srcPort: Int,
        val dstPort: Int,
        val length: Int,
        val checksum: Int,
        val payload: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean =
            other is Datagram && srcPort == other.srcPort && dstPort == other.dstPort &&
                payload.contentEquals(other.payload)

        override fun hashCode(): Int = 31 * (31 * srcPort + dstPort) + payload.contentHashCode()
    }

    fun parse(buf: ByteArray, offset: Int = 0, length: Int = buf.size - offset): Datagram? {
        if (length < 8) return null
        val bb = ByteBuffer.wrap(buf, offset, length).order(ByteOrder.BIG_ENDIAN)
        val src = bb.short.toInt() and 0xffff
        val dst = bb.short.toInt() and 0xffff
        val len = bb.short.toInt() and 0xffff
        val csum = bb.short.toInt() and 0xffff
        if (len < 8 || len > length) return null
        val payload = buf.copyOfRange(offset + 8, offset + len)
        return Datagram(src, dst, len, csum, payload)
    }

    fun build(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
    ): ByteArray {
        val len = 8 + payload.size
        val udp = ByteBuffer.allocate(len).order(ByteOrder.BIG_ENDIAN)
        udp.putShort(srcPort.toShort())
        udp.putShort(dstPort.toShort())
        udp.putShort(len.toShort())
        udp.putShort(0)
        udp.put(payload)
        val arr = udp.array()
        val csum = transportChecksum(srcIp, dstIp, Ipv4Packet.PROTO_UDP, arr)
        arr[6] = ((csum ushr 8) and 0xff).toByte()
        arr[7] = (csum and 0xff).toByte()
        // RFC 768: checksum 0 means no checksum; if computed 0, store 0xffff
        if (arr[6].toInt() == 0 && arr[7].toInt() == 0) {
            arr[6] = 0xff.toByte()
            arr[7] = 0xff.toByte()
        }
        return arr
    }
}

/** ICMP Echo Request/Reply (RFC 792). */
object IcmpEcho {
    const val TYPE_ECHO_REPLY: Int = 0
    const val TYPE_ECHO_REQUEST: Int = 8

    data class Message(val type: Int, val code: Int, val identifier: Int, val sequence: Int, val data: ByteArray)

    fun parse(buf: ByteArray, offset: Int = 0, length: Int = buf.size - offset): Message? {
        if (length < 8) return null
        val type = buf[offset].toInt() and 0xff
        val code = buf[offset + 1].toInt() and 0xff
        val id = ((buf[offset + 4].toInt() and 0xff) shl 8) or (buf[offset + 5].toInt() and 0xff)
        val seq = ((buf[offset + 6].toInt() and 0xff) shl 8) or (buf[offset + 7].toInt() and 0xff)
        val data = buf.copyOfRange(offset + 8, offset + length)
        return Message(type, code, id, seq, data)
    }

    fun buildEchoReply(request: Message): ByteArray {
        val len = 8 + request.data.size
        val arr = ByteArray(len)
        arr[0] = TYPE_ECHO_REPLY.toByte()
        arr[1] = 0
        arr[4] = ((request.identifier ushr 8) and 0xff).toByte()
        arr[5] = (request.identifier and 0xff).toByte()
        arr[6] = ((request.sequence ushr 8) and 0xff).toByte()
        arr[7] = (request.sequence and 0xff).toByte()
        System.arraycopy(request.data, 0, arr, 8, request.data.size)
        val csum = InternetChecksum.compute(arr)
        arr[2] = ((csum ushr 8) and 0xff).toByte()
        arr[3] = (csum and 0xff).toByte()
        return arr
    }
}

internal fun transportChecksum(srcIp: ByteArray, dstIp: ByteArray, proto: Int, segment: ByteArray): Int {
    var sum = 0L
    fun add16(hi: Int, lo: Int) {
        sum += ((hi and 0xff) shl 8) or (lo and 0xff)
    }
    for (i in 0 until 4 step 2) add16(srcIp[i].toInt(), srcIp[i + 1].toInt())
    for (i in 0 until 4 step 2) add16(dstIp[i].toInt(), dstIp[i + 1].toInt())
    add16(0, proto)
    add16((segment.size ushr 8) and 0xff, segment.size and 0xff)
    var i = 0
    while (i + 1 < segment.size) {
        add16(segment[i].toInt(), segment[i + 1].toInt())
        i += 2
    }
    if (i < segment.size) add16(segment[i].toInt(), 0)
    return InternetChecksum.fold(sum)
}
