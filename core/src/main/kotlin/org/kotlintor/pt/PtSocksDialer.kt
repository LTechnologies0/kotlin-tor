package org.kotlintor.pt

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets

/**
 * SOCKS5 client dialer for pluggable-transport CMETHOD endpoints.
 * Connects to [socksHost]:[socksPort] and requests CONNECT to [targetHost]:[targetPort].
 */
object PtSocksDialer {
    fun connect(
        socksHost: String,
        socksPort: Int,
        targetHost: String,
        targetPort: Int,
        connectTimeoutMs: Int = 20_000,
        protect: Boolean = true,
    ): Socket {
        val sock = Socket()
        if (protect) {
            if (!sock.isBound && org.kotlintor.os.PlatformNatives.hasSocketProtector()) {
                runCatching { sock.bind(InetSocketAddress(0)) }
            }
            val ok = org.kotlintor.os.PlatformNatives.protectSocket(sock)
            if (!ok && org.kotlintor.os.PlatformNatives.hasSocketProtector()) {
                runCatching { sock.close() }
                error("VPN protect failed before PT SOCKS dial — refusing clearnet/TUN-loop dial" +
                    (org.kotlintor.os.PlatformNatives.lastProtectFailure?.let { " ($it)" }.orEmpty()))
            }
        }
        sock.connect(InetSocketAddress(socksHost, socksPort), connectTimeoutMs)
        sock.soTimeout = connectTimeoutMs
        val input = DataInputStream(sock.getInputStream())
        val output = DataOutputStream(sock.getOutputStream())
        output.write(byteArrayOf(0x05, 0x01, 0x00))
        output.flush()
        if (input.readUnsignedByte() != 5 || input.readUnsignedByte() != 0) {
            sock.close()
            error("PT SOCKS5 auth rejected")
        }
        val hostBytes = targetHost.toByteArray(StandardCharsets.UTF_8)
        require(hostBytes.size in 1..255)
        output.writeByte(0x05)
        output.writeByte(0x01) // CONNECT
        output.writeByte(0x00)
        output.writeByte(0x03) // DOMAIN
        output.writeByte(hostBytes.size)
        output.write(hostBytes)
        output.writeShort(targetPort)
        output.flush()
        if (input.readUnsignedByte() != 5) {
            sock.close()
            error("PT SOCKS5 bad version")
        }
        val status = input.readUnsignedByte()
        input.readUnsignedByte() // rsv
        val atyp = input.readUnsignedByte()
        when (atyp) {
            0x01 -> input.skipBytes(4)
            0x03 -> input.skipBytes(input.readUnsignedByte())
            0x04 -> input.skipBytes(16)
            else -> {
                sock.close()
                error("PT SOCKS5 bad atyp=$atyp")
            }
        }
        input.skipBytes(2) // port
        if (status != 0) {
            sock.close()
            error("PT SOCKS5 CONNECT failed status=$status")
        }
        return sock
    }

    fun parseSocksAddress(addr: String): Pair<String, Int> {
        val idx = addr.lastIndexOf(':')
        require(idx > 0) { "bad socks address: $addr" }
        return addr.substring(0, idx) to addr.substring(idx + 1).toInt()
    }
}

/**
 * Parsed Bridge line: optional transport, host:port, fingerprint, args.
 * Examples: `obfs4 1.2.3.4:443 FINGERPRINT cert=… iat-mode=0` or `1.2.3.4:443 FINGERPRINT`.
 */
data class BridgeLine(
    val transport: String?,
    val host: String,
    val port: Int,
    val fingerprintHex: String?,
    val args: Map<String, String>,
) {
    companion object {
        fun parse(line: String): BridgeLine? {
            val parts = line.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
            if (parts.isEmpty()) return null
            var i = 0
            var transport: String? = null
            val first = parts[0]
            if (!(first.contains(':') && first.firstOrNull()?.isDigit() == true)) {
                transport = first
                i = 1
            }
            if (i >= parts.size) return null
            val addr = parts[i++]
            val host = addr.substringBefore(':')
            val port = addr.substringAfter(':').toIntOrNull() ?: return null
            var fp: String? = null
            val args = linkedMapOf<String, String>()
            while (i < parts.size) {
                val p = parts[i++]
                when {
                    p.contains('=') -> {
                        val k = p.substringBefore('=')
                        val v = p.substringAfter('=')
                        args[k] = v
                    }
                    p.length >= 40 && p.all { it.isDigit() || it in 'A'..'F' || it in 'a'..'f' } ->
                        fp = p.filter { it != ' ' }
                }
            }
            return BridgeLine(transport, host, port, fp, args)
        }
    }
}
