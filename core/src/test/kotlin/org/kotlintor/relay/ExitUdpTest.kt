package org.kotlintor.relay

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

class ExitUdpTest {
    @Test
    fun `policy gate and echo`() {
        val policy = ExitPolicy.fromTorrcLines(listOf("reject *:80", "accept *:*"))
        val udp = ExitUdp(policy)
        val id = udp.open()
        val echo = DatagramSocket(0)
        echo.soTimeout = 2000
        val port = echo.localPort
        val payload = "ping".toByteArray()
        assertTrue(udp.send(id, "127.0.0.1", port, payload))
        val buf = ByteArray(64)
        val pkt = DatagramPacket(buf, buf.size)
        echo.receive(pkt)
        assertTrue(pkt.length == 4)
        assertFalse(udp.send(id, "127.0.0.1", 80, payload)) // reject :80
        udp.close(id)
        echo.close()
    }
}
