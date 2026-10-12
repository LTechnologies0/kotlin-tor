package org.kotlintor.dir

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.kotlintor.crypto.Digests
import org.kotlintor.util.readTextCompat
import org.kotlintor.util.toHex
import org.kotlintor.util.writeTextCompat
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.zip.InflaterInputStream

/**
 * Fetches consensus / microdescriptors / authority certs.
 *
 * Transport:
 * - [beginDirGet] (BEGIN_DIR on a directory guard) when attached — **required** once a
 *   circuit exists (no cleartext fallback).
 * - Otherwise protected TCP HTTP via [DirHttp] / [OutboundBind] (VpnService.protect).
 */
class DirectoryClient(
    private val cacheDir: Path,
    private val authorities: List<DirectoryAuthority> = DefaultAuthorities.ALL,
) {
    /**
     * BEGIN_DIR GET. When non-null, all directory fetches go through it.
     * Fail-closed: never fall back to cleartext HTTP while this is set.
     */
    @Volatile
    var beginDirGet: (suspend (path: String) -> ByteArray)? = null

    /** True when an OR circuit exists — refuse MITM-able dirport HTTP. */
    @Volatile
    var circuitExists: Boolean = false

    init {
        Files.createDirectories(cacheDir)
    }

    fun pinnedFingerprints(): Set<String> = authorities.map { it.v3Ident }.toSet()

    suspend fun fetchConsensus(force: Boolean = false): Consensus = withContext(Dispatchers.IO) {
        fetchStatusDocument(
            cacheName = "cached-consensus",
            path = "/tor/status-vote/current/consensus",
            parse = { ConsensusParser.parse(it) },
            force = force,
        )
    }

    /** Fetch microdescriptor-flavored consensus (preferred for HSDir ring completeness). */
    suspend fun fetchMicrodescConsensus(force: Boolean = false): Consensus = withContext(Dispatchers.IO) {
        fetchStatusDocument(
            cacheName = "cached-microdesc-consensus",
            path = "/tor/status-vote/current/consensus-microdesc",
            parse = { MicrodescConsensusParser.parse(it) },
            force = force,
            keepPrevious = true,
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
     * with `=` stripped and `/` → `-` (dir-spec). Each returned body is keyed by hex SHA-256
     * and verified against the requested digest (no positional firstOrNull).
     */
    suspend fun fetchMicrodescriptors(digests: List<ByteArray>): Map<String, String> =
        withContext(Dispatchers.IO) {
            if (digests.isEmpty()) return@withContext emptyMap()
            val wanted = digests.associateBy { it.toHex().lowercase() }
            val joined = digests.joinToString("-") { microDescId(it) }
            val text = maybeInflate(directoryGet("/tor/micro/d/$joined"))
            val docs = MicrodescParser.splitDocuments(text)
            val map = LinkedHashMap<String, String>()
            for (doc in docs) {
                val d = MicrodescParser.sha256(doc)
                val hex = d.toHex().lowercase()
                if (hex in wanted) {
                    map[hex] = doc
                }
            }
            val missing = wanted.keys - map.keys
            if (missing.isNotEmpty() && wanted.size == 1 && docs.size == 1) {
                error("microdesc digest mismatch: wanted ${wanted.keys} got ${MicrodescParser.sha256(docs[0]).toHex()}")
            }
            map
        }

    /**
     * Fetch server descriptors by identity fingerprint (hex). Each document is
     * verified: SHA1(descriptor) must match [expectedDigests] when provided.
     * No firstOrNull fallback to an unrelated document.
     */
    suspend fun fetchServerDescriptors(
        fingerprintsHex: List<String>,
        expectedDigests: Map<String, ByteArray> = emptyMap(),
    ): Map<String, String> =
        withContext(Dispatchers.IO) {
            if (fingerprintsHex.isEmpty()) return@withContext emptyMap()
            val want = fingerprintsHex.map { it.uppercase() }.toSet()
            val joined = want.joinToString("+")
            val text = maybeInflate(directoryGet("/tor/server/fp/$joined"))
            val docs = splitServerDescriptors(text)
            val out = LinkedHashMap<String, String>()
            for ((fp, doc) in docs) {
                val key = fp.uppercase()
                if (key !in want) continue
                val expected = expectedDigests[key] ?: expectedDigests.entries
                    .firstOrNull { it.key.equals(key, true) }?.value
                if (expected != null) {
                    val got = Digests.sha1(doc.toByteArray(Charsets.US_ASCII))
                    if (!got.contentEquals(expected)) {
                        error("descriptor SHA1 mismatch for $key")
                    }
                }
                out[key] = doc
            }
            out
        }

    /** Fetch and pin authority certificates to [pinnedFingerprints]. */
    suspend fun fetchAndPinAuthorityCerts(): List<AuthorityCert.Parsed> = withContext(Dispatchers.IO) {
        val pinned = pinnedFingerprints().map { it.replace(" ", "").uppercase() }.toSet()
        val out = ArrayList<AuthorityCert.Parsed>()
        var last: Exception? = null
        try {
            val text = maybeInflate(directoryGet("/tor/keys/all"))
            for (doc in splitCerts(text)) {
                val parsed = runCatching { AuthorityCert.parse(doc) }.getOrNull() ?: continue
                val fp = parsed.fingerprintHex.replace(" ", "").uppercase()
                if (fp !in pinned) continue
                if (!AuthorityCert.verify(parsed)) continue
                AuthCert.put(parsed)
                out += parsed
            }
        } catch (e: Exception) {
            last = e
        }
        if (out.size < DirAuthQuorum.requiredSignatures(pinned.size.coerceAtLeast(1))) {
            for (fp in pinned) {
                if (out.any { it.fingerprintHex.replace(" ", "").equals(fp, true) }) continue
                try {
                    val text = maybeInflate(directoryGet("/tor/keys/fp/$fp"))
                    val parsed = AuthorityCert.parse(text)
                    val got = parsed.fingerprintHex.replace(" ", "").uppercase()
                    if (got != fp) error("authority cert fingerprint $got != pinned $fp")
                    if (!AuthorityCert.verify(parsed)) error("authority cert verify failed for $fp")
                    AuthCert.put(parsed)
                    out += parsed
                } catch (e: Exception) {
                    last = e
                }
            }
        }
        if (out.isEmpty()) {
            throw IllegalStateException("failed to fetch pinned authority certs", last)
        }
        out
    }

    private suspend fun fetchStatusDocument(
        cacheName: String,
        path: String,
        parse: (String) -> Consensus,
        force: Boolean,
        keepPrevious: Boolean = false,
    ): Consensus {
        val cached = cacheDir.resolve(cacheName)
        var cachedConsensus: Consensus? = null
        if (!force && Files.exists(cached)) {
            val text = cached.readTextCompat()
            val c = runCatching { parse(text) }.getOrNull()
            if (c != null && c.isValidAt()) {
                val certs = AuthCert.authorityCertGetAll().ifEmpty {
                    runCatching { fetchAndPinAuthorityCerts() }.getOrDefault(emptyList())
                }
                val v = ConsensusVerifier.verify(c, certs, pinnedFingerprints(), minValidAfter = null)
                if (v.ok) return c
            }
            cachedConsensus = c
        }
        var last: Exception? = null
        val auths = authorities.shuffled()
        for (auth in auths) {
            try {
                val body = directoryGet(path, preferAuth = auth)
                val text = maybeInflate(body)
                val consensus = parse(text)
                if (!consensus.isValidAt()) {
                    throw IllegalStateException(
                        "rejected consensus: valid-after=${consensus.validAfter} valid-until=${consensus.validUntil}",
                    )
                }
                if (cachedConsensus != null && consensus.validAfter.isBefore(cachedConsensus.validAfter)) {
                    throw IllegalStateException(
                        "rejected consensus older than cache ${cachedConsensus.validAfter}",
                    )
                }
                val certs = fetchAndPinAuthorityCerts()
                val v = ConsensusVerifier.verify(
                    consensus,
                    certs,
                    pinnedFingerprints(),
                    minValidAfter = cachedConsensus?.validAfter,
                )
                if (!v.ok) {
                    throw IllegalStateException("consensus signature: ${v.reason}")
                }
                if (keepPrevious && Files.exists(cached)) {
                    Files.move(
                        cached,
                        cacheDir.resolve("$cacheName.prev"),
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    )
                }
                cached.writeTextCompat(text)
                return consensus
            } catch (e: Exception) {
                last = e
            }
        }
        throw IllegalStateException(
            "failed to fetch $path from all authorities: ${last?.javaClass?.simpleName}: ${last?.message}",
            last,
        )
    }

    private suspend fun directoryGet(path: String, preferAuth: DirectoryAuthority? = null): ByteArray {
        val via = beginDirGet
        if (via != null) {
            return via(path)
        }
        if (circuitExists) {
            error("BEGIN_DIR path required: refusing cleartext directory HTTP while a circuit exists")
        }
        var last: Exception? = null
        val order = if (preferAuth != null) {
            listOf(preferAuth) + authorities.filter { it !== preferAuth }
        } else {
            authorities.shuffled()
        }
        for (auth in order) {
            try {
                return DirHttp.get(auth.address, auth.dirPort, path)
            } catch (e: Exception) {
                last = e
            }
        }
        throw IllegalStateException("directory GET $path failed", last)
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
        }
        flush()
        return map
    }

    private fun splitCerts(body: String): List<String> {
        val docs = mutableListOf<String>()
        val sb = StringBuilder()
        for (line in body.lineSequence()) {
            if (line.startsWith("dir-key-certificate-version") && sb.isNotEmpty()) {
                docs += sb.toString()
                sb.clear()
            }
            sb.appendLine(line)
        }
        if (sb.isNotEmpty()) docs += sb.toString()
        return docs
    }

    private fun maybeInflate(body: ByteArray): String {
        if (body.size >= 2 && body[0] == 0x78.toByte()) {
            return InflaterInputStream(body.inputStream()).bufferedReader(StandardCharsets.UTF_8).readText()
        }
        return body.toString(StandardCharsets.UTF_8)
    }
}

/** Optional SOCKS-tunneled directory fetch after bootstrap. */
class SocksDirectoryClient(private val socksHost: String, private val socksPort: Int) {
    fun httpGet(url: String): String {
        val uri = java.net.URI(url)
        val proxy = java.net.Proxy(
            java.net.Proxy.Type.SOCKS,
            java.net.InetSocketAddress(socksHost, socksPort),
        )
        val conn = (uri.toURL().openConnection(proxy) as java.net.HttpURLConnection).apply {
            connectTimeout = 30_000
            readTimeout = 60_000
        }
        return java.io.BufferedReader(
            java.io.InputStreamReader(conn.inputStream, StandardCharsets.UTF_8),
        ).readText()
    }
}
