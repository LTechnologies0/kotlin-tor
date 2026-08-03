package org.kotlintor.relay

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Exit UDP datagram helper (C Tor has no full UDP exit; this is kotlin-tor's
 * clearnet UDP side for gateway / ASSOCIATE tunnels when [ExitPolicy] allows).
 *
 * Native Tor cells still carry TCP; this only performs the last-hop UDP I/O.
 */
class ExitUdp(
    private val policy: ExitPolicy,
    private val maxSockets: Int = 64,
    private val maxPacketBytes: Int = 65507,
) {
    private val nextId = AtomicLong(1)
    private val sockets = ConcurrentHashMap<Long, DatagramSocket>()

    data class Recv(val host: String, val port: Int, val data: ByteArray)

    fun open(): Long {
        require(sockets.size < maxSockets) { "udp exit socket limit" }
        val id = nextId.getAndIncrement()
        sockets[id] = DatagramSocket()
        return id
    }

    fun close(id: Long) {
        sockets.remove(id)?.close()
    }

    fun send(id: Long, host: String, port: Int, data: ByteArray): Boolean {
        if (port !in 1..65535) return false
        if (data.size > maxPacketBytes) return false
        if (!policy.allows(host, port)) return false
        val sock = sockets[id] ?: return false
        val addr = InetAddress.getByName(host)
        sock.send(DatagramPacket(data, data.size, addr, port))
        return true
    }

    fun receive(id: Long, timeoutMs: Int = 1_000): Recv? {
        val sock = sockets[id] ?: return null
        sock.soTimeout = timeoutMs.coerceAtLeast(1)
        val buf = ByteArray(maxPacketBytes)
        val pkt = DatagramPacket(buf, buf.size)
        return try {
            sock.receive(pkt)
            Recv(
                host = pkt.address.hostAddress,
                port = pkt.port,
                data = pkt.data.copyOf(pkt.length),
            )
        } catch (_: Exception) {
            null
        }
    }

    fun size(): Int = sockets.size

    fun closeAll() {
        sockets.keys.toList().forEach { close(it) }
    }
}
