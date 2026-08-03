package org.kotlintor.pt

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URI
import java.nio.charset.StandardCharsets

/**
 * BridgeDB / Moat circumvention API client.
 *
 * Clearnet [fetchSettings] for when bridges are not yet required.
 * [fetchSettingsViaSocks] tunnels Moat through an existing SOCKS5H hop
 * (Tor SOCKS or a meek/obfs4 PT CMETHOD endpoint).
 */
class BridgeDbClient(
    private val moatUrl: String = DEFAULT_MOAT_SETTINGS,
) {
    data class CircumventionSettings(
        val country: String?,
        val bridges: List<String>,
        val rawJson: String,
    )

    suspend fun fetchSettings(country: String? = null): CircumventionSettings = withContext(Dispatchers.IO) {
        val url = buildUrl(country)
        val conn = (URI(url).toURL().openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 20_000
            readTimeout = 30_000
            setRequestProperty("User-Agent", "kotlin-tor/0.1")
            setRequestProperty("Accept", "application/json")
        }
        readResponse(conn, country)
    }

    /**
     * Fetch Moat settings through SOCKS5H (domain remains opaque to the proxy).
     * Use kotlin-tor's own SOCKS once bootstrapped, or a meek PT SOCKS port.
     */
    suspend fun fetchSettingsViaSocks(
        socksHost: String,
        socksPort: Int,
        country: String? = null,
    ): CircumventionSettings = withContext(Dispatchers.IO) {
        val uri = URI(buildUrl(country))
        require(uri.scheme == "https" || uri.scheme == "http") { "unsupported moat scheme" }
        val host = uri.host ?: error("moat host missing")
        val port = if (uri.port > 0) uri.port else if (uri.scheme == "https") 443 else 80
        val path = buildString {
            append(uri.rawPath.ifBlank { "/" })
            if (!uri.rawQuery.isNullOrBlank()) append('?').append(uri.rawQuery)
        }
        // Java Proxy.Type.SOCKS does not do SOCKS5H; dial via PtSocksDialer then TLS upgrade.
        val raw = PtSocksDialer.connect(socksHost, socksPort, host, port)
        try {
            val sock = if (uri.scheme == "https") {
                val factory = javax.net.ssl.SSLSocketFactory.getDefault() as javax.net.ssl.SSLSocketFactory
                val ssl = factory.createSocket(raw, host, port, true) as javax.net.ssl.SSLSocket
                ssl.startHandshake()
                ssl
            } else {
                raw
            }
            val out = DataOutputStream(sock.getOutputStream())
            val req = buildString {
                append("GET $path HTTP/1.1\r\n")
                append("Host: $host\r\n")
                append("User-Agent: kotlin-tor/0.1\r\n")
                append("Accept: application/json\r\n")
                append("Connection: close\r\n\r\n")
            }
            out.write(req.toByteArray(StandardCharsets.US_ASCII))
            out.flush()
            val bytes = sock.getInputStream().readBytes()
            val text = bytes.toString(StandardCharsets.UTF_8)
            val sep = text.indexOf("\r\n\r\n")
            require(sep >= 0) { "Moat SOCKS: bad HTTP response" }
            val statusLine = text.substring(0, text.indexOf('\r'))
            val code = statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: 0
            val body = text.substring(sep + 4)
            if (code !in 200..299) error("Moat SOCKS HTTP $code: ${body.take(200)}")
            CircumventionSettings(country, extractBridgeLines(body), body)
        } finally {
            runCatching { raw.close() }
        }
    }

    /** Convenience: SOCKS Proxy object for HttpURLConnection clearnet-style paths. */
    fun httpProxy(socksHost: String, socksPort: Int): Proxy =
        Proxy(Proxy.Type.SOCKS, InetSocketAddress(socksHost, socksPort))

    fun extractBridgeLines(json: String): List<String> {
        val out = mutableListOf<String>()
        val re = Regex("\"((?:obfs4|snowflake|meek_lite|webtunnel)[^\"]+)\"")
        for (m in re.findAll(json)) {
            out += m.groupValues[1]
                .replace("\\/", "/")
                .replace("\\\"", "\"")
        }
        return out.distinct()
    }

    private fun buildUrl(country: String?): String =
        if (country.isNullOrBlank()) moatUrl else "$moatUrl?country=$country"

    private fun readResponse(conn: HttpURLConnection, country: String?): CircumventionSettings {
        val code = conn.responseCode
        val body = runCatching {
            (if (code in 200..299) conn.inputStream else conn.errorStream)
                ?.readBytes()?.toString(StandardCharsets.UTF_8).orEmpty()
        }.getOrDefault("")
        if (code !in 200..299) {
            error("Moat HTTP $code: ${body.take(200)}")
        }
        return CircumventionSettings(country, extractBridgeLines(body), body)
    }

    companion object {
        const val DEFAULT_MOAT_SETTINGS =
            "https://bridges.torproject.org/moat/circumvention/settings"
        /** Moat domain-front meek target hint (external meek PT must be configured). */
        const val DEFAULT_MEEK_FRONT = "ajax.aspnetcdn.com"
        const val DEFAULT_MEEK_URL = "https://moat.torproject.org.global.prod.fastly.net/"
    }
}
