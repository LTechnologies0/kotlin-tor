package org.kotlintor.dir

import org.kotlintor.net.OutboundBind
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.charset.StandardCharsets

/**
 * Directory HTTP/1.0 over a **protected** TCP socket ([OutboundBind] + VpnService.protect).
 * Used for bootstrap when no BEGIN_DIR circuit exists yet. Never uses
 * [java.net.HttpURLConnection] (that path cannot be VpnService.protect()'d).
 */
object DirHttp {
    const val MAX_BODY_BYTES: Int = 2 * 1024 * 1024

    fun get(host: String, port: Int, path: String, timeoutMs: Int = 60_000): ByteArray {
        requireHttpToken(host, "Host")
        requireHttpPath(path)
        val sock = OutboundBind.connect(host, port, bindHost = null, timeoutMs = 15_000)
        try {
            sock.soTimeout = timeoutMs
            val req =
                "GET $path HTTP/1.0\r\n" +
                    "Host: $host\r\n" +
                    "Accept-Encoding: identity\r\n" +
                    "User-Agent: kotlin-tor/0.1\r\n" +
                    "\r\n"
            sock.getOutputStream().write(req.toByteArray(StandardCharsets.US_ASCII))
            sock.getOutputStream().flush()
            val raw = readBounded(sock.getInputStream(), MAX_BODY_BYTES)
            return splitHttpBody(raw)
        } finally {
            runCatching { sock.close() }
        }
    }

    fun splitHttpBody(raw: ByteArray): ByteArray {
        val sep = findHeaderBodySep(raw) ?: error("directory HTTP: no header terminator")
        val header = raw.copyOfRange(0, sep).toString(StandardCharsets.ISO_8859_1)
        val status = header.lineSequence().firstOrNull()?.trim().orEmpty()
        val code = Regex("^HTTP/1\\.\\d\\s+(\\d+)").find(status)?.groupValues?.get(1)?.toIntOrNull()
            ?: error("directory HTTP: no status in '$status'")
        check(code in 200..299) { "directory HTTP $code ($status)" }
        return raw.copyOfRange(sep, raw.size)
    }

    suspend fun httpGetOverPipe(
        write: suspend (ByteArray) -> Unit,
        readAll: suspend () -> ByteArray,
        path: String,
    ): ByteArray {
        requireHttpPath(path)
        val req =
            "GET $path HTTP/1.0\r\n" +
                "Host: 0.0.0.0\r\n" +
                "Accept-Encoding: identity\r\n" +
                "User-Agent: kotlin-tor/0.1\r\n" +
                "\r\n"
        write(req.toByteArray(StandardCharsets.US_ASCII))
        val raw = readAll()
        check(raw.size <= MAX_BODY_BYTES) { "directory HTTP body exceeds $MAX_BODY_BYTES" }
        return splitHttpBody(raw)
    }

    private fun findHeaderBodySep(raw: ByteArray): Int? {
        for (i in 0 until raw.size - 3) {
            if (raw[i] == '\r'.code.toByte() && raw[i + 1] == '\n'.code.toByte() &&
                raw[i + 2] == '\r'.code.toByte() && raw[i + 3] == '\n'.code.toByte()
            ) {
                return i + 4
            }
        }
        for (i in 0 until raw.size - 1) {
            if (raw[i] == '\n'.code.toByte() && raw[i + 1] == '\n'.code.toByte()) {
                return i + 2
            }
        }
        return null
    }

    fun drain(write: (ByteArray) -> Unit, chunks: Sequence<ByteArray>, maxBytes: Int = MAX_BODY_BYTES): ByteArray {
        write(ByteArray(0))
        val out = ByteArrayOutputStream()
        for (c in chunks) {
            out.write(c)
            if (out.size() > maxBytes) error("directory HTTP body exceeds $maxBytes")
        }
        return out.toByteArray()
    }

    fun readBounded(input: InputStream, maxBytes: Int = MAX_BODY_BYTES): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        var total = 0
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            total += n
            if (total > maxBytes) error("directory HTTP body exceeds $maxBytes")
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    private fun requireHttpPath(path: String) {
        require(path.startsWith("/")) { "directory HTTP: path must be absolute" }
        requireHttpToken(path, "path")
        require(' ' !in path && '\t' !in path) { "directory HTTP: path contains whitespace" }
    }

    private fun requireHttpToken(s: String, label: String) {
        require(s.isNotEmpty() && s.none { it == '\r' || it == '\n' || it == '\u0000' }) {
            "directory HTTP: bad $label"
        }
    }
}
