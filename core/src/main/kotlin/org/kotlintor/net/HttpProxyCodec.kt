package org.kotlintor.net

import java.nio.charset.StandardCharsets

/**
 * HTTP/1.1 proxy surface beyond CONNECT (RFC 9110):
 * absolute-form requests, OPTIONS capability probe, prop365 response headers.
 */
object HttpProxyCodec {
    const val SOFTWARE = "kotlin-tor"
    const val VERSION = "0.1.0-SNAPSHOT"
    const val CAPABILITIES = "isolation,family-preference,optimistic-data"

    sealed class Message {
        data class Connect(val request: HttpConnectCodec.Request) : Message()
        data class Options(val target: String, val headers: Map<String, String>) : Message()
        /** Absolute-form GET/HEAD/POST/… to be forwarded over Tor. */
        data class Absolute(
            val method: String,
            val endpoint: NetEndpoint,
            val pathAndQuery: String,
            val httpVersion: String,
            val headers: Map<String, String>,
            val isolationKey: String?,
            val familyPreference: FamilyPreference,
            val rawHead: ByteArray,
        ) : Message()
    }

    fun parse(raw: ByteArray): Message? {
        val text = raw.toString(StandardCharsets.ISO_8859_1)
        val headerEnd = text.indexOf("\r\n\r\n")
        if (headerEnd < 0) return null
        val head = text.substring(0, headerEnd)
        val lines = head.split("\r\n")
        if (lines.isEmpty()) return null
        val reqLine = lines[0]
        val method = reqLine.substringBefore(' ').uppercase()
        val rest = reqLine.substringAfter(' ').trim()
        val target = rest.substringBefore(' ')
        val ver = rest.substringAfter(' ', "HTTP/1.1").trim()
        val headers = linkedMapOf<String, String>()
        for (i in 1 until lines.size) {
            val line = lines[i]
            val colon = line.indexOf(':')
            if (colon > 0) {
                headers[line.substring(0, colon).trim().lowercase()] = line.substring(colon + 1).trim()
            }
        }
        when (method) {
            "CONNECT" -> {
                val c = HttpConnectCodec.parseRequest(raw) ?: return null
                return Message.Connect(c)
            }
            "OPTIONS" -> return Message.Options(target, headers)
            "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH" -> {
                if (!target.startsWith("http://", ignoreCase = true) &&
                    !target.startsWith("https://", ignoreCase = true)
                ) {
                    // origin-form — not a proxy absolute request
                    return null
                }
                val uri = parseAbsoluteUri(target) ?: return null
                val isolation = headers["x-tor-stream-isolation"]
                    ?: HttpConnectCodec.parseBasicProxyAuth(headers["proxy-authorization"])
                return Message.Absolute(
                    method = method,
                    endpoint = uri.first,
                    pathAndQuery = uri.second,
                    httpVersion = ver,
                    headers = headers,
                    isolationKey = isolation,
                    familyPreference = FamilyPreference.parse(headers["x-tor-family-preference"]),
                    rawHead = raw.copyOfRange(0, headerEnd + 4),
                )
            }
            else -> return null
        }
    }

    /** Returns (endpoint, path+query). Default ports 80/443 by scheme. */
    fun parseAbsoluteUri(uri: String): Pair<NetEndpoint, String>? {
        val lower = uri.lowercase()
        val schemeEnd = uri.indexOf("://")
        if (schemeEnd < 0) return null
        val scheme = lower.substring(0, schemeEnd)
        var rest = uri.substring(schemeEnd + 3)
        val pathIdx = rest.indexOf('/')
        val authority = if (pathIdx < 0) rest else rest.substring(0, pathIdx)
        val path = if (pathIdx < 0) "/" else rest.substring(pathIdx)
        val hostPort = authority.substringAfter('@') // drop userinfo
        val host: String
        val port: Int
        if (hostPort.startsWith("[")) {
            val end = hostPort.indexOf(']')
            if (end < 0) return null
            host = hostPort.substring(1, end)
            port = hostPort.substring(end + 1).removePrefix(":").toIntOrNull()
                ?: defaultPort(scheme)
        } else {
            val colon = hostPort.lastIndexOf(':')
            if (colon > 0 && hostPort.indexOf(':') == colon) {
                host = hostPort.substring(0, colon)
                port = hostPort.substring(colon + 1).toIntOrNull() ?: return null
            } else {
                host = hostPort
                port = defaultPort(scheme)
            }
        }
        if (scheme == "https") {
            // Absolute-form https:// cannot be forwarded as cleartext HTTP over Tor BEGIN;
            // clients should use CONNECT. Reject at parse for safety.
            return null
        }
        return NetEndpoint.parseHostPort(host, port) to path
    }

    private fun defaultPort(scheme: String): Int = when (scheme) {
        "https" -> 443
        else -> 80
    }

    fun torResponseHeaders(): Map<String, String> = linkedMapOf(
        "Server" to "x-tor/1.0 ($SOFTWARE $VERSION)",
        "Via" to "x-tor/1.0 tor-network ($SOFTWARE $VERSION)",
        "X-Tor-Capabilities" to CAPABILITIES,
    )

    fun optionsResponse(): ByteArray = HttpConnectCodec.encodeResponse(
        200,
        "OK",
        torResponseHeaders() + mapOf(
            "Allow" to "CONNECT, OPTIONS, GET, HEAD, POST, PUT, DELETE, PATCH",
        ),
    )

    fun connectionEstablished(): ByteArray = HttpConnectCodec.encodeResponse(
        200,
        "Connection Established",
        torResponseHeaders(),
    )

    /**
     * Rebuild origin-form request for the exit (absolute-form → origin-form).
     */
    fun toOriginForm(abs: Message.Absolute, body: ByteArray = ByteArray(0)): ByteArray {
        val sb = StringBuilder()
        sb.append(abs.method).append(' ').append(abs.pathAndQuery).append(' ')
            .append(abs.httpVersion).append("\r\n")
        val hopByHop = setOf(
            "proxy-connection", "proxy-authorization", "connection", "keep-alive",
            "te", "transfer-encoding", "upgrade", "x-tor-stream-isolation",
            "x-tor-family-preference",
        )
        var sawHost = false
        for ((k, v) in abs.headers) {
            if (k in hopByHop) continue
            if (k == "host") sawHost = true
            sb.append(k).append(": ").append(v).append("\r\n")
        }
        if (!sawHost) {
            sb.append("Host: ").append(abs.endpoint.hostString())
            if (abs.endpoint.port != 80) sb.append(':').append(abs.endpoint.port)
            sb.append("\r\n")
        }
        sb.append("\r\n")
        return sb.toString().toByteArray(StandardCharsets.ISO_8859_1) + body
    }
}
