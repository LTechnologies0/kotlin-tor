package org.kotlintor.net.stack

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.net.MemoryBytePipe
import org.kotlintor.net.TcpHeader

class TunIpStackTest {
    @Test
    fun `ipv4 checksum roundtrip`() {
        val src = Ipv4Packet.parseAddress("10.0.0.1")
        val dst = Ipv4Packet.parseAddress("1.2.3.4")
        val wire = Ipv4Packet.build(src, dst, Ipv4Packet.PROTO_UDP, byteArrayOf(1, 2, 3, 4))
        val p = Ipv4Packet.parse(wire)!!
        assertEquals("10.0.0.1", p.srcString())
        assertEquals("1.2.3.4", p.dstString())
        assertEquals(0, InternetChecksum.compute(wire, 0, 20))
    }

    @Test
    fun `udp checksum and parse`() {
        val src = Ipv4Packet.parseAddress("10.0.0.2")
        val dst = Ipv4Packet.parseAddress("8.8.8.8")
        val udp = UdpDatagram.build(src, dst, 12345, 53, byteArrayOf(0xab.toByte(), 0xcd.toByte()))
        val dg = UdpDatagram.parse(udp)!!
        assertEquals(12345, dg.srcPort)
        assertEquals(53, dg.dstPort)
        assertEquals(2, dg.payload.size)
    }

    @Test
    fun `icmp echo reply via stack`() {
        runBlocking {
            val out = Channel<ByteArray>(Channel.BUFFERED)
            val stack = TunIpStack(
                scope = this,
                emit = { out.send(it) },
                openTcp = { _, _ -> error("no tcp") },
            )
            val src = Ipv4Packet.parseAddress("10.8.0.2")
            val dst = Ipv4Packet.parseAddress("1.1.1.1")
            val echoReq = ByteArray(8 + 4)
            echoReq[0] = IcmpEcho.TYPE_ECHO_REQUEST.toByte()
            echoReq[4] = 0x12
            echoReq[5] = 0x34
            echoReq[6] = 0x00
            echoReq[7] = 0x01
            echoReq[8] = 1; echoReq[9] = 2; echoReq[10] = 3; echoReq[11] = 4
            val csum = InternetChecksum.compute(echoReq)
            echoReq[2] = ((csum ushr 8) and 0xff).toByte()
            echoReq[3] = (csum and 0xff).toByte()
            stack.inject(Ipv4Packet.build(src, dst, Ipv4Packet.PROTO_ICMP, echoReq))
            val replyIp = withTimeout(2_000) { out.receive() }
            val ip = Ipv4Packet.parse(replyIp)!!
            assertEquals("1.1.1.1", ip.srcString())
            assertEquals("10.8.0.2", ip.dstString())
            val icmp = IcmpEcho.parse(ip.payload)!!
            assertEquals(IcmpEcho.TYPE_ECHO_REPLY, icmp.type)
            assertEquals(0x1234, icmp.identifier)
            out.close()
        }
    }

    @Test
    fun `tcp syn gets syn-ack and bridges payload`() {
        runBlocking {
            val out = Channel<ByteArray>(Channel.BUFFERED)
            val remote = MemoryBytePipe()
            val stack = TunIpStack(
                scope = this,
                emit = { out.send(it) },
                openTcp = { host, port ->
                    assertEquals("93.184.216.34", host)
                    assertEquals(80, port)
                    remote
                },
            )
            val client = Ipv4Packet.parseAddress("10.8.0.2")
            val server = Ipv4Packet.parseAddress("93.184.216.34")
            val syn = TcpSegment.build(
                client, server, 40000, 80,
                seq = 1000L, ack = 0L, flags = TcpSegment.FLAG_SYN,
            )
            stack.inject(Ipv4Packet.build(client, server, Ipv4Packet.PROTO_TCP, syn))
            val synAckPkt = withTimeout(2_000) { out.receive() }
            val synAckIp = Ipv4Packet.parse(synAckPkt)!!
            val synAck = TcpHeader.parse(synAckIp.payload)!!
            assertTrue(synAck.syn && synAck.ackFlag)
            assertEquals(1001L, synAck.ack)

            // Let runHandshakeAndBridge reach inbound.receive() before client ACK+data.
            delay(50)
            val ack = TcpSegment.build(
                client, server, 40000, 80,
                seq = 1001L, ack = synAck.seq + 1, flags = TcpSegment.FLAG_ACK,
                payload = "GET / HTTP/1.0\r\n\r\n".toByteArray(),
            )
            stack.inject(Ipv4Packet.build(client, server, Ipv4Packet.PROTO_TCP, ack))
            val buf = ByteArray(64)
            val n = withTimeout(2_000) { remote.read(buf) }
            assertTrue(n > 0)
            assertTrue(buf.copyOf(n).toString(Charsets.US_ASCII).startsWith("GET /"))
            assertEquals(1, stack.activeTcpFlows())
            remote.close()
            delay(50)
            out.close()
            coroutineContext[kotlinx.coroutines.Job]?.cancelChildren()
        }
    }
}
