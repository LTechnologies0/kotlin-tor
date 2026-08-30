package org.kotlintor.net

import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets

/**
 * HAProxy PROXY protocol v1 header (C Tor `proto_haproxy.c`).
 *
 * Inventory: `L1:core/proto/proto_haproxy.c`
 *
 * C Tor `haproxy_format_proxy_header_line`:
 * `PROXY TCP4|TCP6 <unspec-src> <dst> 0 <port>\r\n`
 * Returns null when the destination address family is not IPv4/IPv6.
 */
object ProtoHaproxy {
    private val IPV4 =
        Regex("""^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$""")

    /**
     * C Tor `haproxy_format_proxy_header_line` — [dstHost] must be an IP literal
     * (hostname → null, matching unknown `sa_family`).
     */
    fun formatProxyHeaderLine(dstHost: String, dstPort: Int): String? {
        if (dstHost.isEmpty() || dstPort !in 1..65535) return null
        val family: String
        val src: String
        when {
            dstHost.contains(':') -> {
                family = "TCP6"
                src = "::"
            }
            IPV4.matches(dstHost) -> {
                family = "TCP4"
                src = "0.0.0.0"
            }
            else -> return null
        }
        return "PROXY $family $src $dstHost 0 $dstPort\r\n"
    }

    data class Parsed(
        val family: String,
        val src: String,
        val dst: String,
        val srcPort: Int,
        val dstPort: Int,
    )

    /** Parse a PROXY v1 line (without requiring trailing CRLF). */
    fun parseProxyHeaderLine(line: String): Parsed? {
        val t = line.trim().removeSuffix("\r")
        val parts = t.split(' ')
        if (parts.size < 6 || parts[0] != "PROXY") return null
        val family = parts[1]
        if (family != "TCP4" && family != "TCP6" && family != "UNKNOWN") return null
        if (family == "UNKNOWN") return Parsed(family, "", "", 0, 0)
        val srcPort = parts[4].toIntOrNull() ?: return null
        val dstPort = parts[5].toIntOrNull() ?: return null
        return Parsed(family, parts[2], parts[3], srcPort, dstPort)
    }

    /** Write PROXY v1 on [sock] after TCP connect to a TCPProxy (C Tor connection path). */
    fun injectAfterConnect(sock: Socket, dstHost: String, dstPort: Int) {
        val line = formatProxyHeaderLine(dstHost, dstPort)
            ?: error("HAProxy PROXY: destination address family unsupported ($dstHost)")
        val bytes = line.toByteArray(StandardCharsets.US_ASCII)
        sock.getOutputStream().write(bytes)
        sock.getOutputStream().flush()
    }
}

/** Historical alias — prefer [ProtoHaproxy]. */
typealias HaproxyProxyHeader = ProtoHaproxy
