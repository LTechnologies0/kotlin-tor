package org.kotlintor.dir

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.kotlintor.util.toHex
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.Executors

/**
 * In-process multi-authority peer network (TestingTorNetwork harness).
 *
 * Spins N ephemeral DirPorts, each with vote + consensus-signature inboxes,
 * exchanges documents until [DirAuthQuorum] is met.
 */
class DirAuthPeerNetwork(
    private val authorities: List<AuthorityCert.Material>,
    private val workDir: Path,
) {
    init {
        require(authorities.size >= 2) { "need ≥2 authorities" }
    }

    data class Peer(
        val material: AuthorityCert.Material,
        val fingerprint: String,
        val dirPort: Int,
        val cache: DirCache,
        val voteInbox: DirAuthVoteInbox,
        val sigInbox: DirAuthSigInbox,
        val dataDir: Path,
    )

    data class RoundResult(
        val votesExchanged: Int,
        val signaturesExchanged: Int,
        val quorum: Boolean,
        val mergedSignatures: Int,
        val attachedConsensus: String?,
    )

    /**
     * Start listeners, gossip votes then detached signatures, merge on peer0.
     */
    suspend fun runQuorumRound(): RoundResult = withContext(Dispatchers.IO) {
        Files.createDirectories(workDir)
        val peers = ArrayList<Peer>()
        val sockets = ArrayList<ServerSocket>()
        try {
            for ((i, auth) in authorities.withIndex()) {
                val fp = auth.identityFingerprint.toHex().lowercase()
                val dataDir = workDir.resolve("auth-$i")
                Files.createDirectories(dataDir)
                val voteInbox = DirAuthVoteInbox()
                val sigInbox = DirAuthSigInbox()
                val cache = DirCache(dataDir, voteInbox = voteInbox, sigInbox = sigInbox)
                val ss = ServerSocket()
                ss.bind(InetSocketAddress("127.0.0.1", 0))
                sockets += ss
                serve(ss, cache)
                peers += Peer(auth, fp, ss.localPort, cache, voteInbox, sigInbox, dataDir)
            }

            val known = peers.map { it.fingerprint }.toSet()
            // Each authority collates empty votes → body, signs, gossips vote+sig.
            val bodies = peers.map { p ->
                val session = MultiAuthQuorumSession(listOf(p.material), dataDir = p.dataDir)
                session.publish(stopAtQuorum = false)
            }

            var votes = 0
            var sigs = 0
            for (i in peers.indices) {
                val from = peers[i]
                val voteDoc = "network-status-version 3\nvote-status vote\nfingerprint ${from.fingerprint}\n"
                val det = bodies[i].detached
                for (j in peers.indices) {
                    if (i == j) continue
                    val to = peers[j]
                    val vr = DirAuthVoteGossip.postVote("127.0.0.1", to.dirPort, voteDoc, fromFp = from.fingerprint)
                    if (vr.code in 200..299) votes++
                    val sr = DirAuthVoteGossip.postConsensusSignature(
                        "127.0.0.1",
                        to.dirPort,
                        det,
                        fromFp = from.fingerprint,
                    )
                    if (sr.code in 200..299) sigs++
                }
            }

            // Merge detached docs on peer 0 (peers' POSTs + local)
            val collected = peers[0].sigInbox.all().values.toList() + listOf(bodies[0].detached)
            val merged = if (collected.isEmpty()) {
                DetachedSignatures.parse(bodies[0].detached)
            } else {
                MultiAuthQuorumSession(authorities).mergeDetached(collected)
            }
            val quorum = DirAuthQuorum.fromDetached(merged, known)
            val attached = DetachedSignatures.attachToConsensus(bodies[0].body, merged.signatures)
            Files.writeString(peers[0].dataDir.resolve("cached-consensus"), attached)
            Files.writeString(
                peers[0].dataDir.resolve("cached-consensus-diff"),
                DetachedSignatures.formatDetached(
                    bodies[0].body,
                    merged.validAfter ?: "2020-01-01 00:00:00",
                    merged.freshUntil ?: "2020-01-01 00:00:00",
                    merged.validUntil ?: "2020-01-01 00:00:00",
                    merged.signatures,
                ),
            )
            RoundResult(votes, sigs, quorum, merged.signatures.size, attached)
        } finally {
            sockets.forEach { runCatching { it.close() } }
        }
    }

    private fun serve(ss: ServerSocket, cache: DirCache) {
        Executors.newSingleThreadExecutor().execute {
            while (!ss.isClosed) {
                runCatching {
                    val sock = ss.accept()
                    Executors.newSingleThreadExecutor().execute {
                        try {
                            val input = sock.getInputStream()
                            val header = java.io.ByteArrayOutputStream()
                            val b = ByteArray(1)
                            while (header.size() < 65536) {
                                if (input.read(b) <= 0) break
                                header.write(b[0].toInt())
                                if (header.toString(StandardCharsets.US_ASCII).contains("\r\n\r\n")) break
                            }
                            val headers = header.toString(StandardCharsets.US_ASCII)
                            val len = headers.lineSequence()
                                .firstOrNull { it.startsWith("Content-Length:", ignoreCase = true) }
                                ?.substringAfter(':')?.trim()?.toIntOrNull() ?: 0
                            val body = if (len > 0) input.readNBytes(len.coerceAtMost(2_000_000)) else ByteArray(0)
                            sock.getOutputStream().write(cache.handleHttp(headers, body))
                        } finally {
                            runCatching { sock.close() }
                        }
                    }
                }
            }
        }
    }
}

/**
 * Parse torrc `DirAuthority` / `FallbackDir` lines into [DirectoryAuthority].
 *
 * Accepts subset: `nickname orport=N [v3ident=HEX] address:dirport [fingerprint]`
 * or simplified `nickname address:dirport`.
 */
object DirAuthorityConfig {
    fun parseDirAuthority(line: String): DirectoryAuthority? {
        val parts = line.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
        if (parts.isEmpty()) return null
        val nickname = parts[0]
        var orPort = 0
        var v3 = ""
        var addrPort: String? = null
        for (p in parts.drop(1)) {
            when {
                p.startsWith("orport=", true) -> orPort = p.substringAfter('=').toIntOrNull() ?: 0
                p.startsWith("v3ident=", true) -> v3 = p.substringAfter('=')
                p.contains(':') && addrPort == null -> addrPort = p
                p.length >= 40 && p.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' } ->
                    if (v3.isEmpty()) v3 = p
            }
        }
        val ap = addrPort ?: return null
        val host = ap.substringBeforeLast(':')
        val dirPort = ap.substringAfterLast(':').toIntOrNull() ?: return null
        return DirectoryAuthority(
            nickname = nickname,
            address = host,
            dirPort = dirPort,
            orPort = orPort,
            v3Ident = v3.uppercase(),
        )
    }

    fun parseFallbackDir(line: String): DirectoryAuthority? {
        val parts = line.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
        if (parts.isEmpty()) return null
        var host = ""
        var orPort = 0
        var dirPort = 80
        var id = ""
        for (p in parts) {
            when {
                p.startsWith("orport=", true) -> orPort = p.substringAfter('=').toIntOrNull() ?: orPort
                p.startsWith("id=", true) -> id = p.substringAfter('=')
                p.contains(':') && !p.contains('=') -> {
                    host = p.substringBeforeLast(':')
                    orPort = p.substringAfterLast(':').toIntOrNull() ?: orPort
                }
            }
        }
        if (host.isEmpty()) return null
        return DirectoryAuthority(
            nickname = "Fallback",
            address = host,
            dirPort = dirPort,
            orPort = orPort,
            v3Ident = id.uppercase(),
        )
    }
}
