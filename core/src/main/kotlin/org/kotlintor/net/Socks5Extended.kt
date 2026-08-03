package org.kotlintor.net

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.nio.charset.StandardCharsets

/** Result of SOCKS5 handshake after auth (RFC 1928 CMD). */
sealed class Socks5Outcome {
    data class Connect(val route: TorRouteRequest) : Socks5Outcome()
    data class Bind(
        val requested: NetEndpoint,
        val isolationKey: String?,
        val clientAddr: String?,
    ) : Socks5Outcome()
    data class UdpAssociate(
        val clientHint: NetEndpoint,
        val isolationKey: String?,
        val clientAddr: String?,
    ) : Socks5Outcome()
}

/** RFC 1928 §7 UDP request header. */
object Socks5UdpCodec {
    data class Datagram(
        val frag: Int,
        val endpoint: NetEndpoint,
        val data: ByteArray,
    )

    fun parse(buf: ByteArray, offset: Int = 0, length: Int = buf.size - offset): Datagram? {
        if (length < 4) return null
        val frag = buf[offset + 2].toInt() and 0xff
        if (frag != 0) return null
        val atyp = buf[offset + 3].toInt() and 0xff
        var o = offset + 4
        val endpoint: NetEndpoint = when (atyp) {
            Socks5Codec.ATYP_IPV4 -> {
                if (length - (o - offset) < 6) return null
                val addr = buf.copyOfRange(o, o + 4)
                o += 4
                val port = ((buf[o].toInt() and 0xff) shl 8) or (buf[o + 1].toInt() and 0xff)
                o += 2
                NetEndpoint.Ipv4(addr, port)
            }
            Socks5Codec.ATYP_DOMAIN -> {
                if (length - (o - offset) < 1) return null
                val len = buf[o].toInt() and 0xff
                o++
                if (length - (o - offset) < len + 2) return null
                val name = buf.copyOfRange(o, o + len).toString(StandardCharsets.UTF_8)
                o += len
                val port = ((buf[o].toInt() and 0xff) shl 8) or (buf[o + 1].toInt() and 0xff)
                o += 2
                NetEndpoint.Domain(name, port)
            }
            Socks5Codec.ATYP_IPV6 -> {
                if (length - (o - offset) < 18) return null
                val addr = buf.copyOfRange(o, o + 16)
                o += 16
                val port = ((buf[o].toInt() and 0xff) shl 8) or (buf[o + 1].toInt() and 0xff)
                o += 2
                NetEndpoint.Ipv6(addr, port)
            }
            else -> return null
        }
        val data = buf.copyOfRange(o, offset + length)
        return Datagram(frag, endpoint, data)
    }

    fun encode(endpoint: NetEndpoint, data: ByteArray): ByteArray {
        val header = when (endpoint) {
            is NetEndpoint.Ipv4 -> byteArrayOf(0, 0, 0, Socks5Codec.ATYP_IPV4.toByte()) +
                endpoint.octets +
                byteArrayOf(((endpoint.port ushr 8) and 0xff).toByte(), (endpoint.port and 0xff).toByte())
            is NetEndpoint.Ipv6 -> byteArrayOf(0, 0, 0, Socks5Codec.ATYP_IPV6.toByte()) +
                endpoint.octets +
                byteArrayOf(((endpoint.port ushr 8) and 0xff).toByte(), (endpoint.port and 0xff).toByte())
            is NetEndpoint.Domain -> {
                val name = endpoint.name.toByteArray(StandardCharsets.UTF_8)
                byteArrayOf(0, 0, 0, Socks5Codec.ATYP_DOMAIN.toByte(), name.size.toByte()) + name +
                    byteArrayOf(((endpoint.port ushr 8) and 0xff).toByte(), (endpoint.port and 0xff).toByte())
            }
        }
        return header + data
    }
}

/**
 * Local SOCKS5 BIND (RFC 1928): listen, first reply with bind addr, second after accept.
 */
suspend fun socks5BindAccept(
    local: BytePipe,
    bindHost: String = "127.0.0.1",
    timeoutMs: Long = 120_000,
): java.net.Socket? = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
    val ss = ServerSocket()
    ss.bind(InetSocketAddress(bindHost, 0))
    ss.soTimeout = timeoutMs.toInt().coerceAtLeast(1_000)
    val localPort = ss.localPort
    val ip = InetAddress.getByName(bindHost).address.let {
        if (it.size == 4) it else byteArrayOf(127, 0, 0, 1)
    }
    val bindEp = NetEndpoint.Ipv4(ip, localPort)
    local.write(Socks5Codec.encodeReply(Socks5Codec.Reply(Socks5Reply.Succeeded, bindEp)))
    val peer = try {
        ss.accept()
    } catch (_: Exception) {
        local.write(Socks5Codec.encodeReply(Socks5Codec.Reply(Socks5Reply.GeneralFailure)))
        ss.close()
        return@withContext null
    }
    ss.close()
    val peerAddr = peer.inetAddress?.address ?: byteArrayOf(0, 0, 0, 0)
    val peerEp = if (peerAddr.size == 4) {
        NetEndpoint.Ipv4(peerAddr, peer.port)
    } else {
        NetEndpoint.Ipv6(peerAddr, peer.port)
    }
    local.write(Socks5Codec.encodeReply(Socks5Codec.Reply(Socks5Reply.Succeeded, peerEp)))
    peer
}

/**
 * Local SOCKS5 UDP ASSOCIATE: reply with UDP bind, relay until TCP control closes.
 * Clearnet UDP only (Tor UDP exit not wired).
 */
suspend fun socks5UdpAssociateRelay(
    control: BytePipe,
    clientHint: NetEndpoint,
): Unit = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
    val udp = DatagramSocket(0)
    val bindEp = NetEndpoint.Ipv4(byteArrayOf(127, 0, 0, 1), udp.localPort)
    control.write(Socks5Codec.encodeReply(Socks5Codec.Reply(Socks5Reply.Succeeded, bindEp)))
    val buf = ByteArray(65535)
    val expected = when (clientHint) {
        is NetEndpoint.Ipv4 ->
            if (clientHint.octets.contentEquals(byteArrayOf(0, 0, 0, 0))) null
            else InetAddress.getByAddress(clientHint.octets)
        else -> null
    }
    try {
        while (!control.isClosed()) {
            val packet = DatagramPacket(buf, buf.size)
            udp.soTimeout = 500
            try {
                udp.receive(packet)
            } catch (_: java.net.SocketTimeoutException) {
                continue
            }
            if (expected != null && packet.address != expected) continue
            val dg = Socks5UdpCodec.parse(packet.data, 0, packet.length) ?: continue
            val target = when (val e = dg.endpoint) {
                is NetEndpoint.Ipv4 -> InetSocketAddress(InetAddress.getByAddress(e.octets), e.port)
                is NetEndpoint.Ipv6 -> InetSocketAddress(InetAddress.getByAddress(e.octets), e.port)
                is NetEndpoint.Domain -> InetSocketAddress(e.name, e.port)
            }
            udp.send(DatagramPacket(dg.data, dg.data.size, target))
            val replyBuf = ByteArray(65535)
            val replyPkt = DatagramPacket(replyBuf, replyBuf.size)
            udp.soTimeout = 3_000
            try {
                udp.receive(replyPkt)
                val addr = replyPkt.address.address.let { if (it.size == 4) it else byteArrayOf(0, 0, 0, 0) }
                val wrapped = Socks5UdpCodec.encode(
                    NetEndpoint.Ipv4(addr, replyPkt.port),
                    replyBuf.copyOf(replyPkt.length),
                )
                udp.send(DatagramPacket(wrapped, wrapped.size, packet.socketAddress))
            } catch (_: Exception) {
                // silent drop
            }
        }
    } finally {
        udp.close()
    }
}
