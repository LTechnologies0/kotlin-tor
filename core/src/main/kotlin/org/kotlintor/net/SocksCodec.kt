package org.kotlintor.net

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets

/**
 * RFC 1928 SOCKS5 + RFC 1929 Username/Password — pure encode/decode (no I/O).
 */
object Socks5Codec {
    const val VERSION: Int = 0x05
    const val AUTH_NONE: Int = 0x00
    const val AUTH_USERPASS: Int = 0x02
    const val AUTH_NO_ACCEPTABLE: Int = 0xFF
    const val USERPASS_VERSION: Int = 0x01

    const val ATYP_IPV4: Int = 0x01
    const val ATYP_DOMAIN: Int = 0x03
    const val ATYP_IPV6: Int = 0x04

    data class MethodOffer(val methods: List<Int>)
    data class MethodSelect(val method: Int)
    data class UserPassRequest(val username: String, val password: String)
    data class UserPassStatus(val ok: Boolean)
    data class Request(val command: Socks5Command, val endpoint: NetEndpoint)
    data class Reply(val reply: Socks5Reply, val bind: NetEndpoint = NetEndpoint.Ipv4(byteArrayOf(0, 0, 0, 0), 0))

    fun parseMethodOffer(buf: ByteArray, offset: Int = 0): Pair<MethodOffer, Int>? {
        if (buf.size - offset < 2) return null
        if (buf[offset].toInt() and 0xff != VERSION) return null
        val n = buf[offset + 1].toInt() and 0xff
        if (buf.size - offset < 2 + n) return null
        val methods = (0 until n).map { buf[offset + 2 + it].toInt() and 0xff }
        return MethodOffer(methods) to (2 + n)
    }

    fun encodeMethodSelect(method: Int): ByteArray = byteArrayOf(VERSION.toByte(), method.toByte())

    fun parseUserPassRequest(buf: ByteArray, offset: Int = 0): Pair<UserPassRequest, Int>? {
        if (buf.size - offset < 2) return null
        if (buf[offset].toInt() and 0xff != USERPASS_VERSION) return null
        val ulen = buf[offset + 1].toInt() and 0xff
        if (buf.size - offset < 2 + ulen + 1) return null
        val user = buf.copyOfRange(offset + 2, offset + 2 + ulen).toString(StandardCharsets.UTF_8)
        val plen = buf[offset + 2 + ulen].toInt() and 0xff
        if (buf.size - offset < 2 + ulen + 1 + plen) return null
        val pass = buf.copyOfRange(offset + 3 + ulen, offset + 3 + ulen + plen).toString(StandardCharsets.UTF_8)
        return UserPassRequest(user, pass) to (3 + ulen + plen)
    }

    fun encodeUserPassStatus(ok: Boolean): ByteArray =
        byteArrayOf(USERPASS_VERSION.toByte(), if (ok) 0x00 else 0x01)

    fun parseRequest(buf: ByteArray, offset: Int = 0): Pair<Request, Int>? {
        if (buf.size - offset < 4) return null
        if (buf[offset].toInt() and 0xff != VERSION) return null
        val cmd = Socks5Command.from(buf[offset + 1].toInt() and 0xff) ?: return null
        // RSV must be 0
        val atyp = buf[offset + 3].toInt() and 0xff
        var o = offset + 4
        val endpoint: NetEndpoint = when (atyp) {
            ATYP_IPV4 -> {
                if (buf.size - o < 6) return null
                val addr = buf.copyOfRange(o, o + 4)
                o += 4
                val port = ((buf[o].toInt() and 0xff) shl 8) or (buf[o + 1].toInt() and 0xff)
                o += 2
                NetEndpoint.Ipv4(addr, port)
            }
            ATYP_DOMAIN -> {
                if (buf.size - o < 1) return null
                val len = buf[o].toInt() and 0xff
                o++
                if (buf.size - o < len + 2) return null
                val name = buf.copyOfRange(o, o + len).toString(StandardCharsets.UTF_8)
                o += len
                val port = ((buf[o].toInt() and 0xff) shl 8) or (buf[o + 1].toInt() and 0xff)
                o += 2
                NetEndpoint.Domain(name, port)
            }
            ATYP_IPV6 -> {
                if (buf.size - o < 18) return null
                val addr = buf.copyOfRange(o, o + 16)
                o += 16
                val port = ((buf[o].toInt() and 0xff) shl 8) or (buf[o + 1].toInt() and 0xff)
                o += 2
                NetEndpoint.Ipv6(addr, port)
            }
            else -> return null
        }
        return Request(cmd, endpoint) to (o - offset)
    }

    fun encodeReply(reply: Reply): ByteArray {
        val bb = ByteBuffer.allocate(4 + 255 + 2).order(ByteOrder.BIG_ENDIAN)
        bb.put(VERSION.toByte())
        bb.put(reply.reply.code.toByte())
        bb.put(0x00)
        when (val e = reply.bind) {
            is NetEndpoint.Ipv4 -> {
                bb.put(ATYP_IPV4.toByte())
                bb.put(e.octets)
                bb.putShort(e.port.toShort())
            }
            is NetEndpoint.Ipv6 -> {
                bb.put(ATYP_IPV6.toByte())
                bb.put(e.octets)
                bb.putShort(e.port.toShort())
            }
            is NetEndpoint.Domain -> {
                bb.put(ATYP_DOMAIN.toByte())
                val name = e.name.toByteArray(StandardCharsets.UTF_8)
                bb.put(name.size.toByte())
                bb.put(name)
                bb.putShort(e.port.toShort())
            }
        }
        val out = ByteArray(bb.position())
        bb.flip()
        bb.get(out)
        return out
    }

    /** Choose auth: prefer USER/PASS when offered (IsolateSOCKSAuth). */
    fun selectMethod(offer: MethodOffer, preferUserPass: Boolean = true): Int {
        if (preferUserPass && AUTH_USERPASS in offer.methods) return AUTH_USERPASS
        if (AUTH_NONE in offer.methods) return AUTH_NONE
        return AUTH_NO_ACCEPTABLE
    }
}

/**
 * SOCKS4 / SOCKS4a (no formal IETF RFC; de-facto: https://www.openssh.com/txt/socks4.protocol
 * and SOCKS4A extension with DSTIP 0.0.0.x non-zero last octet + domain after USERID).
 */
object Socks4Codec {
    const val VERSION: Int = 0x04
    const val CMD_CONNECT: Int = 0x01
    const val CMD_BIND: Int = 0x02
    const val REP_GRANTED: Int = 90
    const val REP_REJECTED: Int = 91

    data class Request(
        val command: Int,
        val endpoint: NetEndpoint,
        val userId: String,
    )

    fun parseRequest(buf: ByteArray, offset: Int = 0): Pair<Request, Int>? {
        if (buf.size - offset < 8) return null
        if (buf[offset].toInt() and 0xff != VERSION) return null
        val cmd = buf[offset + 1].toInt() and 0xff
        val port = ((buf[offset + 2].toInt() and 0xff) shl 8) or (buf[offset + 3].toInt() and 0xff)
        val ip = buf.copyOfRange(offset + 4, offset + 8)
        var o = offset + 8
        // USERID NUL-terminated
        val userStart = o
        while (o < buf.size && buf[o] != 0.toByte()) o++
        if (o >= buf.size) return null
        val userId = buf.copyOfRange(userStart, o).toString(StandardCharsets.ISO_8859_1)
        o++ // NUL
        val isSocks4a = ip[0] == 0.toByte() && ip[1] == 0.toByte() && ip[2] == 0.toByte() && ip[3] != 0.toByte()
        val endpoint = if (isSocks4a) {
            val dStart = o
            while (o < buf.size && buf[o] != 0.toByte()) o++
            if (o >= buf.size) return null
            val domain = buf.copyOfRange(dStart, o).toString(StandardCharsets.ISO_8859_1)
            o++ // NUL
            NetEndpoint.Domain(domain, port)
        } else {
            NetEndpoint.Ipv4(ip, port)
        }
        return Request(cmd, endpoint, userId) to (o - offset)
    }

    fun encodeReply(status: Int, port: Int = 0, ip: ByteArray = byteArrayOf(0, 0, 0, 0)): ByteArray {
        require(ip.size == 4)
        return byteArrayOf(
            0x00,
            status.toByte(),
            ((port ushr 8) and 0xff).toByte(),
            (port and 0xff).toByte(),
            ip[0], ip[1], ip[2], ip[3],
        )
    }
}
