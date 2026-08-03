package org.kotlintor.dir

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.kotlintor.config.TorrcParser
import org.kotlintor.util.toHex
import java.nio.file.Files
import java.nio.file.Path

/**
 * Two (or N) directory-authority peer processes simulated in-process via
 * [DirAuthPublishLoop] + DirPort HTTP (multi-daemon dirauth harness).
 *
 * Each peer gets its own data dir, RSA authority material, DirPort listener
 * (through [DirAuthPeerNetwork]), and publish loop; votes + detached signatures
 * are gossiped until [DirAuthQuorum].
 */
class TorDaemonDirAuthCluster(
    private val workDir: Path,
    private val nAuthorities: Int = 3,
) {
    data class Result(
        val quorum: Boolean,
        val votesExchanged: Int,
        val signaturesExchanged: Int,
        val fingerprints: List<String>,
        val consensusBytes: Int,
    )

    /**
     * Run one voting/signing round across [nAuthorities] peers.
     * Uses [DirAuthPeerNetwork] under the hood (ephemeral DirPorts).
     */
    fun runQuorumRound(): Result {
        Files.createDirectories(workDir)
        val auths = List(nAuthorities) { AuthorityCert.generate(bits = 1024) }
        val fps = auths.map { it.identityFingerprint.toHex().lowercase() }
        // Persist each authority as a TorConfig-shaped data dir (daemon-like layout).
        for ((i, auth) in auths.withIndex()) {
            val dir = workDir.resolve("daemon-$i")
            val keys = dir.resolve("keys")
            Files.createDirectories(keys)
            AuthorityCert.persist(auth, keys, auth.formatCertificate())
            val torrc = buildString {
                appendLine("DataDirectory $dir")
                appendLine("AuthoritativeDirectory 1")
                appendLine("V3AuthoritativeDirectory 1")
                appendLine("TestingTorNetwork 1")
                appendLine("ORPort 127.0.0.1:0")
                appendLine("DirPort 127.0.0.1:0")
                appendLine("DirAllowPrivateAddresses 1")
                appendLine("AssumeReachable 1")
                appendLine("PublishServerDescriptor 0")
                appendLine("Nickname Auth$i")
            }
            Files.writeString(dir.resolve("torrc"), torrc)
            // Parse to prove torrc shape is valid for TorDaemon.
            TorrcParser.parse(torrc, dir)
        }
        val net = DirAuthPeerNetwork(auths, workDir.resolve("net"))
        val round = runBlocking { net.runQuorumRound() }
        return Result(
            quorum = round.quorum,
            votesExchanged = round.votesExchanged,
            signaturesExchanged = round.signaturesExchanged,
            fingerprints = fps,
            consensusBytes = round.attachedConsensus?.length ?: 0,
        )
    }

    /**
     * Start live [DirAuthPublishLoop]s, gossip detached signatures peer-to-peer,
     * and wait until [DirAuthQuorum] or timeout.
     */
    fun runLivePublishQuorum(
        timeoutMs: Long = 5_000,
        scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default),
    ): Result {
        // Ensure daemon dirs + keys exist.
        val prep = runQuorumRound()
        val fps = prep.fingerprints.map { it.uppercase() }.toSet()
        val loops = startPublishLoops(scope)
        try {
            // Force each loop to publish, then gossip detached to every peer.
            val detached = loops.mapNotNull { it.publishNow()?.second }
            for (loop in loops) {
                for (d in detached) loop.notePeerDetached(d)
            }
            // Re-publish with peer sigs merged.
            var lastBytes = 0
            var quorum = false
            val knownLower = fps.map { it.lowercase() }.toSet()
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                val pubs = loops.mapNotNull { it.publishNow() }
                lastBytes = pubs.maxOfOrNull { it.first.length } ?: 0
                quorum = pubs.any { (_, detached) ->
                    val parsed = DetachedSignatures.parse(detached)
                    DirAuthQuorum.fromDetached(parsed, knownLower)
                }
                if (quorum) break
                // Re-gossip latest detached after each publish round.
                val latest = pubs.map { it.second }
                for (loop in loops) {
                    for (d in latest) loop.notePeerDetached(d)
                }
                Thread.sleep(50)
            }
            return Result(
                quorum = quorum,
                votesExchanged = prep.votesExchanged,
                signaturesExchanged = detached.size.coerceAtLeast(prep.signaturesExchanged),
                fingerprints = prep.fingerprints,
                consensusBytes = lastBytes,
            )
        } finally {
            stopPublishLoops(loops, scope)
        }
    }

    /**
     * Start live [DirAuthPublishLoop]s for each daemon dir (no full TorClient bootstrap).
     */
    fun startPublishLoops(scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)): List<DirAuthPublishLoop> {
        val materials = (0 until nAuthorities).mapNotNull { i ->
            AuthorityCert.loadMaterial(workDir.resolve("daemon-$i/keys"))
        }
        val known = materials.map { it.identityFingerprint.toHex().uppercase() }.toSet()
        val loops = ArrayList<DirAuthPublishLoop>()
        for ((i, material) in materials.withIndex()) {
            val dir = workDir.resolve("daemon-$i")
            val timing = DirVote.Timing(
                voteIntervalSec = DirVote.MIN_VOTE_INTERVAL_TESTING,
                voteSeconds = 2,
                distSeconds = 2,
                testing = true,
            )
            val loop = DirAuthPublishLoop(
                scope = scope,
                dataDir = dir.resolve("dirauth"),
                timing = timing,
                knownAuthorities = known,
                localAuthority = material,
            )
            loop.start()
            loops += loop
        }
        return loops
    }

    fun stopPublishLoops(loops: List<DirAuthPublishLoop>, scope: CoroutineScope? = null) {
        loops.forEach { it.stop() }
        scope?.cancel()
    }
}
