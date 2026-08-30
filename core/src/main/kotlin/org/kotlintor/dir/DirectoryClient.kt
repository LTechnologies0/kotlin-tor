package org.kotlintor.dir

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.kotlintor.util.readTextCompat
import org.kotlintor.util.toHex
import org.kotlintor.util.writeTextCompat
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URI
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.InflaterInputStream

/**
 * Fetches consensus / microdescriptors over clearnet HTTP to directory authorities
 * during bootstrap (same initial model as many clients). Later can switch to BEGIN_DIR.
 */
class DirectoryClient(
    private val cacheDir: Path,
    private val authorities: List<DirectoryAuthority> = DefaultAuthorities.ALL,
) {
    init {
        Files.createDirectories(cacheDir)
    }

    suspend fun fetchConsensus(force: Boolean = false): Consensus = withContext(Dispatchers.IO) {
        val cached = cacheDir.resolve("cached-consensus")
        if (!force && Files.exists(cached)) {
            val text = cached.readTextCompat()
            val c = ConsensusParser.parse(text)
            if (c.isValidAt()) return@withContext c
        }
        var last: Exception? = null
        for (auth in authorities.shuffled()) {
            try {
                val url = "http://${auth.address}:${auth.dirPort}/tor/status-vote/current/consensus"
                val body = httpGet(url)
                val text = maybeInflate(body)
                val consensus = ConsensusParser.parse(text)
                cached.writeTextCompat(text)
                return@withContext consensus
            } catch (e: Exception) {
                last = e
            }
        }
        throw IllegalStateException(
            "failed to fetch consensus from all authorities: ${last?.javaClass?.simpleName}: ${last?.message}",
            last,
        )
    }

    /** Fetch microdescriptor-flavored consensus (preferred for HSDir ring completeness). */
    suspend fun fetchMicrodescConsensus(force: Boolean = false): Consensus = withContext(Dispatchers.IO) {
        val cached = cacheDir.resolve("cached-microdesc-consensus")
        if (!force && Files.exists(cached)) {
            val text = cached.readTextCompat()
            val c = MicrodescConsensusParser.parse(text)
            if (c.isValidAt()) return@withContext c
        }
        var last: Exception? = null
        for (auth in authorities.shuffled()) {
            try {
                val url = "http://${auth.address}:${auth.dirPort}/tor/status-vote/current/consensus-microdesc"
                val body = httpGet(url)
                val text = maybeInflate(body)
                val consensus = MicrodescConsensusParser.parse(text)
                // Keep previous document for HSDir ring overlap during consensus rotation.
                if (Files.exists(cached)) {
                    Files.move(
                        cached,
                        cacheDir.resolve("cached-microdesc-consensus.prev"),
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    )
                }
                cached.writeTextCompat(text)
                return@withContext consensus
            } catch (e: Exception) {
                last = e
            }
        }
        throw IllegalStateException(
            "failed to fetch microdesc consensus: ${last?.javaClass?.simpleName}: ${last?.message}",
            last,
        )
    }

    /** Current + previous microdesc consensuses (previous may be expired but still useful for HSDir lag). */
    suspend fun fetchMicrodescConsensusCandidates(force: Boolean = false): List<Consensus> {
        val current = fetchMicrodescConsensus(force)
        val prevFile = cacheDir.resolve("cached-microdesc-consensus.prev")
        val prev = if (Files.exists(prevFile)) {
            runCatching { MicrodescConsensusParser.parse(prevFile.readTextCompat()) }.getOrNull()
        } else {
            null
        }
        return listOfNotNull(current, prev).distinctBy { it.validAfter }
    }

    /**
     * Fetch microdescriptors. Digests must be SHA-256 of the microdesc; URL uses base64
     * with `=` stripped and `/` → `-` (dir-spec).
     */
    suspend fun fetchMicrodescriptors(digests: List<ByteArray>): Map<String, String> =
        withContext(Dispatchers.IO) {
            if (digests.isEmpty()) return@withContext emptyMap()
            val joined = digests.joinToString("-") { microDescId(it) }
            var last: Exception? = null
            for (auth in authorities.shuffled()) {
                try {
                    val url = "http://${auth.address}:${auth.dirPort}/tor/micro/d/$joined"
                    val body = httpGet(url)
                    val text = maybeInflate(body)
                    val docs = MicrodescParser.splitDocuments(text)
                    if (digests.size == 1 && docs.size == 1) {
                        return@withContext mapOf(digests[0].toHex() to docs[0])
                    }
                    val map = LinkedHashMap<String, String>()
                    for ((i, doc) in docs.withIndex()) {
                        val key = digests.getOrNull(i)?.toHex() ?: "doc-$i"
                        map[key] = doc
                    }
                    return@withContext map
                } catch (e: Exception) {
                    last = e
                }
            }
            throw IllegalStateException("failed to fetch microdescriptors", last)
        }

    /** Fetch server descriptors by identity fingerprint (hex). */
    suspend fun fetchServerDescriptors(fingerprintsHex: List<String>): Map<String, String> =
        withContext(Dispatchers.IO) {
            if (fingerprintsHex.isEmpty()) return@withContext emptyMap()
            val joined = fingerprintsHex.joinToString("+") { it.uppercase() }
            var last: Exception? = null
            for (auth in authorities.shuffled()) {
                try {
                    val url = "http://${auth.address}:${auth.dirPort}/tor/server/fp/$joined"
                    val body = httpGet(url)
                    val text = maybeInflate(body)
                    return@withContext splitServerDescriptors(text)
                } catch (e: Exception) {
                    last = e
                }
            }
            throw IllegalStateException("failed to fetch server descriptors", last)
        }

    private fun microDescId(sha256: ByteArray): String {
        val b64 = java.util.Base64.getEncoder().encodeToString(sha256)
        return b64.trimEnd('=').replace('/', '-')
    }

    private fun splitServerDescriptors(body: String): Map<String, String> {
        val map = LinkedHashMap<String, String>()
        val sb = StringBuilder()
        var fp: String? = null
        fun flush() {
            val f = fp ?: return
            if (sb.isNotEmpty()) map[f] = sb.toString()
            sb.clear()
            fp = null
        }
        for (line in body.lineSequence()) {
            if (line.startsWith("router ")) {
                flush()
            }
            if (line.startsWith("fingerprint ")) {
                fp = line.removePrefix("fingerprint ").replace(" ", "").uppercase()
            }
            sb.appendLine(line)
            if (line == "router-signature") {
                // continue until blank after signature block — keep appending
            }
        }
        flush()
        return map
    }

    private fun httpGet(url: String): ByteArray {
        val conn = (URI(url).toURL().openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 60_000
            setRequestProperty("Accept-Encoding", "identity")
            setRequestProperty("User-Agent", "kotlin-tor/0.1")
            instanceFollowRedirects = true
        }
        conn.inputStream.use { return it.readBytes() }
    }

    private fun maybeInflate(body: ByteArray): String {
        // Consensus may be plain text or zlib (not gzip) compressed depending on server.
        if (body.size >= 2 && body[0] == 0x78.toByte()) {
            return InflaterInputStream(body.inputStream()).bufferedReader(StandardCharsets.UTF_8).readText()
        }
        return body.toString(StandardCharsets.UTF_8)
    }
}

/** Optional SOCKS-tunneled directory fetch after bootstrap. */
class SocksDirectoryClient(private val socksHost: String, private val socksPort: Int) {
    fun httpGet(url: String): String {
        val uri = URI(url)
        val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(socksHost, socksPort))
        val conn = (uri.toURL().openConnection(proxy) as HttpURLConnection).apply {
            connectTimeout = 30_000
            readTimeout = 60_000
        }
        return BufferedReader(InputStreamReader(conn.inputStream, StandardCharsets.UTF_8)).readText()
    }
}
