package org.kotlintor.net

import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * HTTP CONNECT tunnel (RFC 9110 §9.3.6) + Tor prop365 isolation / family headers.
 * Pure parse/encode over ISO-8859-1 request lines.
 */
object HttpConnectCodec {
    data class Request(
        val endpoint: NetEndpoint,
        val httpVersion: String,
        val headers: Map<String, String>,
        val isolationKey: String?,
        val familyPreference: FamilyPreference,
    )

    fun parseRequest(raw: ByteArray): Request? {
        val text = raw.toString(StandardCharsets.ISO_8859_1)
        val headerEnd = text.indexOf("\r\n\r\n")
        if (headerEnd < 0) return null
        val head = text.substring(0, headerEnd)
        val lines = head.split("\r\n")
        if (lines.isEmpty()) return null
        val req = lines[0]
        if (!req.startsWith("CONNECT ", ignoreCase = true)) return null
        val rest = req.removePrefix("CONNECT ").trim()
        val target = rest.substringBefore(' ')
        val ver = rest.substringAfter(' ', "HTTP/1.1").trim()
        val hostPart = target.substringBeforeLast(':')
        val portPart = target.substringAfterLast(':', "443")
        val host = hostPart.removePrefix("[").removeSuffix("]")
        val port = portPart.toIntOrNull() ?: return null
        val headers = linkedMapOf<String, String>()
        for (i in 1 until lines.size) {
            val line = lines[i]
            val colon = line.indexOf(':')
            if (colon > 0) {
                headers[line.substring(0, colon).trim().lowercase()] = line.substring(colon + 1).trim()
            }
        }
        val isolation = headers["x-tor-stream-isolation"]
            ?: parseBasicProxyAuth(headers["proxy-authorization"])
        val family = FamilyPreference.parse(headers["x-tor-family-preference"])
        return Request(
            endpoint = NetEndpoint.parseHostPort(host, port),
            httpVersion = ver,
            headers = headers,
            isolationKey = isolation,
            familyPreference = family,
        )
    }

    /**
     * prop365: applications SHOULD use Basic username `x-tor` with arbitrary password;
     * we still accept any Basic user as isolation key for janky clients (C Tor compat).
     */
    fun parseBasicProxyAuth(header: String?): String? {
        if (header == null) return null
        if (!header.startsWith("Basic ", ignoreCase = true)) return null
        val decoded = runCatching {
            String(Base64.getDecoder().decode(header.removePrefix("Basic ").trim()), StandardCharsets.ISO_8859_1)
        }.getOrNull() ?: return null
        val user = decoded.substringBefore(':')
        return user.ifEmpty { null }
    }

    fun encodeResponse(code: Int, reason: String, extraHeaders: Map<String, String> = emptyMap()): ByteArray {
        val sb = StringBuilder()
        sb.append("HTTP/1.1 ").append(code).append(' ').append(reason).append("\r\n")
        for ((k, v) in extraHeaders) {
            sb.append(k).append(": ").append(v).append("\r\n")
        }
        sb.append("\r\n")
        return sb.toString().toByteArray(StandardCharsets.ISO_8859_1)
    }

    fun connectionEstablished(): ByteArray = HttpProxyCodec.connectionEstablished()
}

/**
 * Prop365 bilingual listen: first byte 0x04/0x05 → SOCKS; 0x16 → TLS; ASCII → HTTP.
 */
enum class LocalProtocol { Socks4, Socks5, Http, Tls, Unknown }

object ProtocolDetector {
    fun detect(firstByte: Int): LocalProtocol = when (firstByte and 0xff) {
        0x04 -> LocalProtocol.Socks4
        0x05 -> LocalProtocol.Socks5
        TlsClientHello.CONTENT_HANDSHAKE -> LocalProtocol.Tls
        in 0x41..0x5A, in 0x61..0x7A -> LocalProtocol.Http
        else -> LocalProtocol.Unknown
    }
}
