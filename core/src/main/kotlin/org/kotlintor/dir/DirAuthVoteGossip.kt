package org.kotlintor.dir

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/**
 * DirAuth vote inbox + HTTP gossip (C Tor dirvote POST `/tor/post/vote`).
 *
 * Authorities POST vote documents to peer DirPorts; receivers store by
 * identity fingerprint for [DirAuthPublishLoop.addPeerVote] / quorum.
 */
class DirAuthVoteInbox(
    private val maxVotes: Int = 64,
) {
    private val byFrom = ConcurrentHashMap<String, String>()
    private val listeners = CopyOnWriteArrayList<(fromFp: String, body: String) -> Unit>()

    fun onVote(listener: (fromFp: String, body: String) -> Unit) {
        listeners += listener
    }

    fun put(fromFp: String, body: String) {
        val key = fromFp.lowercase().ifEmpty { "anon-${body.hashCode()}" }
        if (byFrom.size >= maxVotes && !byFrom.containsKey(key)) {
            byFrom.keys.firstOrNull()?.let { byFrom.remove(it) }
        }
        byFrom[key] = body
        listeners.forEach { it(key, body) }
    }

    fun get(fromFp: String): String? = byFrom[fromFp.lowercase()]

    fun all(): Map<String, String> = byFrom.toMap()

    fun clear() = byFrom.clear()

    fun size(): Int = byFrom.size
}

/**
 * Inbox for peer detached consensus signatures (C Tor POST `/tor/post/consensus-signature`).
 */
class DirAuthSigInbox(
    private val maxDocs: Int = 64,
) {
    private val byFrom = ConcurrentHashMap<String, String>()
    private val listeners = CopyOnWriteArrayList<(fromFp: String, body: String) -> Unit>()

    fun onSig(listener: (fromFp: String, body: String) -> Unit) {
        listeners += listener
    }

    fun put(fromFp: String, body: String) {
        val key = fromFp.lowercase().ifEmpty { "anon-${body.hashCode()}" }
        if (byFrom.size >= maxDocs && !byFrom.containsKey(key)) {
            byFrom.keys.firstOrNull()?.let { byFrom.remove(it) }
        }
        byFrom[key] = body
        listeners.forEach { it(key, body) }
    }

    fun get(fromFp: String): String? = byFrom[fromFp.lowercase()]

    fun all(): Map<String, String> = byFrom.toMap()

    fun clear() = byFrom.clear()

    fun size(): Int = byFrom.size
}

/**
 * HTTP client that POSTs votes to peer authority DirPorts.
 */
object DirAuthVoteGossip {
    data class Result(val peer: String, val code: Int, val body: String)

    suspend fun postVote(
        peerHost: String,
        peerDirPort: Int,
        voteBody: String,
        fromFp: String = "",
    ): Result = post(
        path = "/tor/post/vote",
        peerHost = peerHost,
        peerDirPort = peerDirPort,
        body = voteBody,
        fromFp = fromFp,
    )

    /** C Tor `DIR_PURPOSE_UPLOAD_SIGNATURES` → POST `/tor/post/consensus-signature`. */
    suspend fun postConsensusSignature(
        peerHost: String,
        peerDirPort: Int,
        detachedBody: String,
        fromFp: String = "",
    ): Result = post(
        path = "/tor/post/consensus-signature",
        peerHost = peerHost,
        peerDirPort = peerDirPort,
        body = detachedBody,
        fromFp = fromFp,
    )

    suspend fun gossipSignaturesToPeers(
        peers: List<Pair<String, Int>>,
        detachedBody: String,
        fromFp: String = "",
    ): List<Result> = peers.map { (host, port) ->
        postConsensusSignature(host, port, detachedBody, fromFp)
    }

    suspend fun gossipToPeers(
        peers: List<Pair<String, Int>>,
        voteBody: String,
        fromFp: String = "",
    ): List<Result> = peers.map { (host, port) -> postVote(host, port, voteBody, fromFp) }

    private suspend fun post(
        path: String,
        peerHost: String,
        peerDirPort: Int,
        body: String,
        fromFp: String,
    ): Result = withContext(Dispatchers.IO) {
        val url = "http://$peerHost:$peerDirPort$path"
        try {
            val conn = (URI(url).toURL().openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput = true
                connectTimeout = 10_000
                readTimeout = 30_000
                setRequestProperty("Content-Type", "text/plain")
                setRequestProperty("User-Agent", "kotlin-tor/0.1")
                if (fromFp.isNotEmpty()) setRequestProperty("X-Tor-Authority-Id", fromFp)
            }
            conn.outputStream.use { it.write(body.toByteArray(StandardCharsets.UTF_8)) }
            val code = conn.responseCode
            val resp = runCatching {
                (if (code in 200..299) conn.inputStream else conn.errorStream)
                    ?.readBytes()?.toString(StandardCharsets.UTF_8).orEmpty()
            }.getOrDefault("")
            Result("$peerHost:$peerDirPort", code, resp.take(200))
        } catch (e: Exception) {
            Result("$peerHost:$peerDirPort", -1, e.message ?: "error")
        }
    }
}
