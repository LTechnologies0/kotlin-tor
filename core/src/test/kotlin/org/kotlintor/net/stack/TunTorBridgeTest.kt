package org.kotlintor.net.stack

import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.kotlintor.net.MemoryBytePipe

class TunTorBridgeTest {
    @Test
    fun `memory tun pumps icmp through bridge`() {
        runBlocking {
            val tun = MemoryTun()
            val bridge = TunTorBridge(
                scope = this,
                io = tun,
                openTcp = { _, _ -> MemoryBytePipe() },
            )
            bridge.start()
            val src = Ipv4Packet.parseAddress("10.8.0.2")
            val dst = Ipv4Packet.parseAddress("8.8.8.8")
            val echo = ByteArray(8)
            echo[0] = IcmpEcho.TYPE_ECHO_REQUEST.toByte()
            val csum = InternetChecksum.compute(echo)
            echo[2] = ((csum ushr 8) and 0xff).toByte()
            echo[3] = (csum and 0xff).toByte()
            tun.injectFromDevice(Ipv4Packet.build(src, dst, Ipv4Packet.PROTO_ICMP, echo))
            val out = withTimeout(2_000) { tun.takeEmitted() }
            val ip = Ipv4Packet.parse(out)!!
            assertEquals("8.8.8.8", ip.srcString())
            assertEquals(IcmpEcho.TYPE_ECHO_REPLY, IcmpEcho.parse(ip.payload)!!.type)
            bridge.stop()
        }
    }

    @Test
    fun `memory tun tcp syn reaches openTcp`() {
        runBlocking {
            val tun = MemoryTun()
            var opened: Pair<String, Int>? = null
            val bridge = TunTorBridge(
                scope = this,
                io = tun,
                openTcp = { host, port ->
                    opened = host to port
                    MemoryBytePipe()
                },
            )
            bridge.start()
            val client = Ipv4Packet.parseAddress("10.8.0.2")
            val server = Ipv4Packet.parseAddress("93.184.216.34")
            val syn = TcpSegment.build(
                client, server, 40000, 80,
                seq = 1L, ack = 0L, flags = TcpSegment.FLAG_SYN,
            )
            tun.injectFromDevice(Ipv4Packet.build(client, server, Ipv4Packet.PROTO_TCP, syn))
            withTimeout(2_000) { tun.takeEmitted() } // SYN-ACK
            assertEquals("93.184.216.34" to 80, opened)
            val rst = TcpSegment.build(
                client, server, 40000, 80,
                seq = 2L, ack = 0L, flags = TcpSegment.FLAG_RST,
            )
            tun.injectFromDevice(Ipv4Packet.build(client, server, Ipv4Packet.PROTO_TCP, rst))
            kotlinx.coroutines.delay(50)
            bridge.stop()
            coroutineContext[kotlinx.coroutines.Job]?.cancelChildren()
        }
    }
}
