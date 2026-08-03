package org.kotlintor.net.stack

import org.kotlintor.net.TcpHeader

/** TCP segment with IPv4 pseudo-header checksum (RFC 793 + 1071). */
object TcpSegment {
    const val FLAG_FIN: Int = 0x01
    const val FLAG_SYN: Int = 0x02
    const val FLAG_RST: Int = 0x04
    const val FLAG_PSH: Int = 0x08
    const val FLAG_ACK: Int = 0x10

    fun build(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        window: Int = 65535,
        payload: ByteArray = ByteArray(0),
    ): ByteArray {
        val raw = TcpHeader.build(srcPort, dstPort, seq, ack, flags, window, payload)
        val csum = transportChecksum(srcIp, dstIp, Ipv4Packet.PROTO_TCP, raw)
        raw[16] = ((csum ushr 8) and 0xff).toByte()
        raw[17] = (csum and 0xff).toByte()
        return raw
    }

    fun parse(buf: ByteArray, offset: Int = 0, length: Int = buf.size - offset): TcpHeader.Segment? =
        TcpHeader.parse(buf, offset, length)
}
