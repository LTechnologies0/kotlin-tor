package org.kotlintor.net.stack

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * IPv4 datagram (RFC 791) — pure Kotlin parse/build for TUN userspace stack.
 */
object Ipv4Packet {
    const val PROTO_ICMP: Int = 1
    const val PROTO_TCP: Int = 6
    const val PROTO_UDP: Int = 17

    data class Packet(
        val version: Int,
        val ihl: Int,
        val dscpEcn: Int,
        val totalLength: Int,
        val identification: Int,
        val flagsFrag: Int,
        val ttl: Int,
        val protocol: Int,
        val checksum: Int,
        val src: ByteArray,
        val dst: ByteArray,
        val options: ByteArray,
        val payload: ByteArray,
    ) {
        val headerLength: Int get() = ihl * 4
        val dontFragment: Boolean get() = flagsFrag and 0x4000 != 0
        val moreFragments: Boolean get() = flagsFrag and 0x2000 != 0
        val fragmentOffset: Int get() = flagsFrag and 0x1fff

        fun srcString(): String = src.joinToString(".") { (it.toInt() and 0xff).toString() }
        fun dstString(): String = dst.joinToString(".") { (it.toInt() and 0xff).toString() }

        override fun equals(other: Any?): Boolean =
            other is Packet && src.contentEquals(other.src) && dst.contentEquals(other.dst) &&
                protocol == other.protocol && payload.contentEquals(other.payload)

        override fun hashCode(): Int =
            31 * (31 * src.contentHashCode() + dst.contentHashCode()) + payload.contentHashCode()
    }

    fun parse(buf: ByteArray, offset: Int = 0, length: Int = buf.size - offset): Packet? {
        if (length < 20) return null
        val verIhl = buf[offset].toInt() and 0xff
        val version = verIhl ushr 4
        val ihl = verIhl and 0x0f
        if (version != 4 || ihl < 5) return null
        val hdrLen = ihl * 4
        if (length < hdrLen) return null
        val totalLength = ((buf[offset + 2].toInt() and 0xff) shl 8) or (buf[offset + 3].toInt() and 0xff)
        if (totalLength < hdrLen || totalLength > length) return null
        val id = ((buf[offset + 4].toInt() and 0xff) shl 8) or (buf[offset + 5].toInt() and 0xff)
        val flagsFrag = ((buf[offset + 6].toInt() and 0xff) shl 8) or (buf[offset + 7].toInt() and 0xff)
        val ttl = buf[offset + 8].toInt() and 0xff
        val proto = buf[offset + 9].toInt() and 0xff
        val csum = ((buf[offset + 10].toInt() and 0xff) shl 8) or (buf[offset + 11].toInt() and 0xff)
        val src = buf.copyOfRange(offset + 12, offset + 16)
        val dst = buf.copyOfRange(offset + 16, offset + 20)
        val options = if (hdrLen > 20) buf.copyOfRange(offset + 20, offset + hdrLen) else ByteArray(0)
        val payload = buf.copyOfRange(offset + hdrLen, offset + totalLength)
        return Packet(version, ihl, buf[offset + 1].toInt() and 0xff, totalLength, id, flagsFrag, ttl, proto, csum, src, dst, options, payload)
    }

    fun build(
        src: ByteArray,
        dst: ByteArray,
        protocol: Int,
        payload: ByteArray,
        ttl: Int = 64,
        identification: Int = 0,
        dscpEcn: Int = 0,
    ): ByteArray {
        require(src.size == 4 && dst.size == 4)
        val total = 20 + payload.size
        val bb = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN)
        bb.put(((4 shl 4) or 5).toByte())
        bb.put(dscpEcn.toByte())
        bb.putShort(total.toShort())
        bb.putShort(identification.toShort())
        bb.putShort(0) // flags/frag
        bb.put(ttl.toByte())
        bb.put(protocol.toByte())
        bb.putShort(0) // checksum placeholder
        bb.put(src)
        bb.put(dst)
        bb.put(payload)
        val arr = bb.array()
        val csum = InternetChecksum.compute(arr, 0, 20)
        arr[10] = ((csum ushr 8) and 0xff).toByte()
        arr[11] = (csum and 0xff).toByte()
        return arr
    }

    fun parseAddress(dotted: String): ByteArray {
        val parts = dotted.split('.')
        require(parts.size == 4)
        return byteArrayOf(
            parts[0].toInt().toByte(),
            parts[1].toInt().toByte(),
            parts[2].toInt().toByte(),
            parts[3].toInt().toByte(),
        )
    }
}
