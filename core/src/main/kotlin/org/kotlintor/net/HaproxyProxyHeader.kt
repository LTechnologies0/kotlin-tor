package org.kotlintor.net

/**
 * HAProxy PROXY protocol v1 header (C Tor `proto_haproxy.c`).
 *
 * Inventory: `L1:core/proto/proto_haproxy.c`
 *
 * C Tor formats: `PROXY TCP4|TCP6 <src> <dst> 0 <port>\r\n` with src as
 * unspecified (`0.0.0.0` / `::`) when announcing the destination ORPort.
 */
object HaproxyProxyHeader {
    fun formatProxyHeaderLine(dstHost: String, dstPort: Int): String? {
        if (dstHost.isEmpty() || dstPort <= 0) return null
        val ipv6 = dstHost.contains(':')
        val family = if (ipv6) "TCP6" else "TCP4"
        val src = if (ipv6) "::" else "0.0.0.0"
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
}
