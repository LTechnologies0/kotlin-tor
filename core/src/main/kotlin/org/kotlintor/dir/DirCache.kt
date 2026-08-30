package org.kotlintor.dir

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.Deflater

/**
 * Serve directory documents from the client cache (relay DirPort / BEGIN_DIR subset).
 *
 * Supported URL surface (dir-spec):
 * - `/tor/status-vote/current/consensus[.z]`
 * - `/tor/status-vote/current/consensus-microdesc[.z]`
 * - `/tor/server/fp/<fp>[+fp…]`
 * - `/tor/server/d/<digest>[+digest…]` (SHA1 hex of descriptor)
 * - `/tor/micro/d/<base64urlsha256>[+…]`
 * - `/tor/keys/fp/<fp>` (authority cert cache if present)
 * - `/tor/keys/all` (concatenated authority certs when cached)
 * - `POST /tor/post/vote` (dirauth vote gossip when [voteInbox] set)
 * - `POST /tor/post/consensus-signature` (detached sig gossip when [sigInbox] set)
 */
class DirCache(
    private val cacheDir: Path,
    val voteInbox: DirAuthVoteInbox? = null,
    val sigInbox: DirAuthSigInbox? = null,
) {
    fun handleHttp(request: String, body: ByteArray = ByteArray(0)): ByteArray {
        val first = request.lineSequence().firstOrNull()?.trim().orEmpty()
        val parts = first.split(Regex("\\s+"))
        if (parts.size < 2) {
            return httpResponse(400, "text/plain", "Bad Request\n")
        }
        val method = parts[0].uppercase()
        var path = parts[1]
        val q = path.indexOf('?')
        if (q >= 0) path = path.substring(0, q)
        if (path.startsWith("http://", ignoreCase = true)) {
            path = path.substringAfter("://").substringAfter('/')
            path = "/$path"
        }
        if (method == "POST") {
            return handlePost(path, request, body)
        }
        if (method != "GET") {
            return httpResponse(405, "text/plain", "Method Not Allowed\n")
        }
        return when {
            path == "/tor/status-vote/current/consensus" ||
                path == "/tor/status-vote/current/consensus.z" ->
                serveFile("cached-consensus", compressed = path.endsWith(".z"))
            path == "/tor/status-vote/current/consensus-microdesc" ||
                path == "/tor/status-vote/current/consensus-microdesc.z" ->
                serveFile("cached-microdesc-consensus", compressed = path.endsWith(".z"))
            path.startsWith("/tor/server/fp/") -> {
                val fps = path.removePrefix("/tor/server/fp/").split('+').filter { it.isNotEmpty() }
                serveDescriptors(fps)
            }
            path.startsWith("/tor/server/d/") -> {
                val digests = path.removePrefix("/tor/server/d/").split('+').filter { it.isNotEmpty() }
                serveByDigest(digests)
            }
            path.startsWith("/tor/micro/d/") -> {
                val ids = path.removePrefix("/tor/micro/d/").split('+').filter { it.isNotEmpty() }
                serveMicrodescs(ids)
            }
            path == "/tor/keys/all" -> serveAuthorityKeys()
            path.startsWith("/tor/keys/fp/") -> {
                val fp = path.removePrefix("/tor/keys/fp/").substringBefore('+').uppercase()
                serveFile("cached-certs/$fp", compressed = false)
            }
            path == "/tor/status-vote/next/consensus-signatures" ->
                serveFile("cached-consensus-diff", compressed = false)
            else -> httpResponse(404, "text/plain", "Not found\n")
        }
    }

    private fun handlePost(path: String, headers: String, body: ByteArray): ByteArray {
        return when (path) {
            "/tor/post/vote", "/tor/" -> {
                val inbox = voteInbox
                    ?: return httpResponse(403, "text/plain", "vote inbox disabled\n")
                val from = headers.lineSequence()
                    .firstOrNull { it.startsWith("X-Tor-Authority-Id:", ignoreCase = true) }
                    ?.substringAfter(':')?.trim().orEmpty()
                val text = body.toString(StandardCharsets.UTF_8)
                if (text.isBlank()) return httpResponse(400, "text/plain", "empty vote\n")
                inbox.put(from.ifEmpty { "peer" }, text)
                httpResponse(200, "text/plain", "ok\n")
            }
            "/tor/post/consensus-signature" -> {
                val inbox = sigInbox
                    ?: return httpResponse(403, "text/plain", "sig inbox disabled\n")
                val from = headers.lineSequence()
                    .firstOrNull { it.startsWith("X-Tor-Authority-Id:", ignoreCase = true) }
                    ?.substringAfter(':')?.trim().orEmpty()
                val text = body.toString(StandardCharsets.UTF_8)
                if (text.isBlank()) return httpResponse(400, "text/plain", "empty detached\n")
                if (!text.contains("directory-signature")) {
                    return httpResponse(400, "text/plain", "not a detached-signatures document\n")
                }
                inbox.put(from.ifEmpty { "peer" }, text)
                httpResponse(200, "text/plain", "ok\n")
            }
            else -> httpResponse(404, "text/plain", "Not found\n")
        }
    }

    private fun serveFile(name: String, compressed: Boolean): ByteArray {
        val f = cacheDir.resolve(name)
        if (!Files.exists(f)) {
            return httpResponse(404, "text/plain", "Not cached\n")
        }
        var body = Files.readAllBytes(f)
        if (compressed) {
            body = deflate(body)
        }
        return httpResponse(200, "text/plain", body, compressed)
    }

    private fun serveDescriptors(fingerprintsHex: List<String>): ByteArray {
        if (fingerprintsHex.isEmpty()) {
            return httpResponse(400, "text/plain", "empty fingerprint list\n")
        }
        val sb = StringBuilder()
        var any = false
        for (fp in fingerprintsHex) {
            val f = cacheDir.resolve("cached-descriptors").resolve(fp.uppercase())
            if (Files.exists(f)) {
                sb.append(Files.readString(f))
                if (!sb.endsWith("\n")) sb.append('\n')
                any = true
            }
        }
        return if (any) {
            httpResponse(200, "text/plain", sb.toString().toByteArray(StandardCharsets.UTF_8))
        } else {
            httpResponse(404, "text/plain", "descriptors not cached\n")
        }
    }

    private fun serveByDigest(digests: List<String>): ByteArray {
        val descDir = cacheDir.resolve("cached-descriptors")
        if (!Files.isDirectory(descDir)) {
            return httpResponse(404, "text/plain", "descriptors not cached\n")
        }
        val want = digests.map { it.lowercase() }.toSet()
        val sb = StringBuilder()
        var any = false
        Files.list(descDir).use { stream ->
            stream.filter { Files.isRegularFile(it) }.forEach { f ->
                val body = Files.readString(f)
                val dig = sha1Hex(body.toByteArray(StandardCharsets.UTF_8))
                if (dig in want) {
                    sb.append(body)
                    if (!sb.endsWith("\n")) sb.append('\n')
                    any = true
                }
            }
        }
        return if (any) {
            httpResponse(200, "text/plain", sb.toString().toByteArray(StandardCharsets.UTF_8))
        } else {
            httpResponse(404, "text/plain", "descriptors not cached\n")
        }
    }

    private fun serveMicrodescs(ids: List<String>): ByteArray {
        val microDir = cacheDir.resolve("cached-microdescs")
        if (!Files.isDirectory(microDir) && !Files.exists(cacheDir.resolve("cached-microdescs.new"))) {
            // Fall back: single-file microdesc cache used by DirectoryClient.
            val single = cacheDir.resolve("cached-microdescs")
            if (Files.isRegularFile(single)) {
                val all = Files.readString(single)
                // Best-effort: return whole cache if any id substring matches.
                val hit = ids.any { id -> all.contains(id) }
                return if (hit) {
                    httpResponse(200, "text/plain", all.toByteArray(StandardCharsets.UTF_8))
                } else {
                    httpResponse(404, "text/plain", "microdescs not cached\n")
                }
            }
            return httpResponse(404, "text/plain", "microdescs not cached\n")
        }
        val sb = StringBuilder()
        var any = false
        for (id in ids) {
            val safe = id.replace('/', '_').replace('+', '-')
            val f = microDir.resolve(safe)
            if (Files.exists(f)) {
                sb.append(Files.readString(f))
                if (!sb.endsWith("\n")) sb.append('\n')
                any = true
            }
        }
        return if (any) {
            httpResponse(200, "text/plain", sb.toString().toByteArray(StandardCharsets.UTF_8))
        } else {
            httpResponse(404, "text/plain", "microdescs not cached\n")
        }
    }

    private fun serveAuthorityKeys(): ByteArray {
        val certDir = cacheDir.resolve("cached-certs")
        if (!Files.isDirectory(certDir)) {
            return httpResponse(404, "text/plain", "certs not cached\n")
        }
        val sb = StringBuilder()
        var any = false
        Files.list(certDir).use { stream ->
            stream.filter { Files.isRegularFile(it) }.forEach { f ->
                sb.append(Files.readString(f))
                if (!sb.endsWith("\n")) sb.append('\n')
                any = true
            }
        }
        return if (any) {
            httpResponse(200, "text/plain", sb.toString().toByteArray(StandardCharsets.UTF_8))
        } else {
            httpResponse(404, "text/plain", "certs not cached\n")
        }
    }

    private fun deflate(raw: ByteArray): ByteArray {
        val d = Deflater(Deflater.DEFAULT_COMPRESSION, true)
        d.setInput(raw)
        d.finish()
        val out = ByteArray(raw.size + 64)
        val n = d.deflate(out)
        d.end()
        return out.copyOf(n)
    }

    private fun sha1Hex(data: ByteArray): String {
        val md = java.security.MessageDigest.getInstance("SHA-1")
        return md.digest(data).joinToString("") { b -> "%02x".format(b) }
    }

    private fun httpResponse(
        status: Int,
        contentType: String,
        body: String,
    ): ByteArray = httpResponse(status, contentType, body.toByteArray(StandardCharsets.UTF_8))

    private fun httpResponse(
        status: Int,
        contentType: String,
        body: ByteArray,
        compressed: Boolean = false,
    ): ByteArray {
        val reason = when (status) {
            200 -> "OK"
            400 -> "Bad Request"
            404 -> "Not Found"
            else -> "Error"
        }
        val header = buildString {
            append("HTTP/1.0 $status $reason\r\n")
            append("Content-Type: $contentType\r\n")
            append("Content-Length: ${body.size}\r\n")
            if (compressed) append("Content-Encoding: deflate\r\n")
            append("\r\n")
        }.toByteArray(StandardCharsets.US_ASCII)
        return header + body
    }
}
