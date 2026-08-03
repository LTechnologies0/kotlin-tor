package org.kotlintor.dir

import java.nio.file.Files
import java.nio.file.Path

/**
 * Multi-authority signing session: N [AuthorityCert.Material] authorities each
 * produce RSA detached signatures over the same consensus body until
 * [DirAuthQuorum] is satisfied (TestingTorNetwork / local dirauth harness).
 */
class MultiAuthQuorumSession(
    private val authorities: List<AuthorityCert.Material>,
    private val dataDir: Path? = null,
) {
    init {
        require(authorities.isNotEmpty())
    }

    val knownFingerprints: Set<String> =
        authorities.map { it.identityFingerprint.toHex().lowercase() }.toSet()

    data class Result(
        val body: String,
        val attached: String,
        val detached: String,
        val signatureCount: Int,
        val quorum: Boolean,
    )

    /**
     * Collate empty vote set into a minimal consensus body, then collect
     * signatures from every authority (or until quorum if [stopAtQuorum]).
     */
    fun publish(
        actorVotes: List<BandwidthVote.VoteDocument> = emptyList(),
        stopAtQuorum: Boolean = false,
        validAfter: String = "2020-01-01 00:00:00",
    ): Result {
        val collated = DirCollator.collate(actorVotes, authorities.size.coerceAtLeast(1))
        val body = DirCollator.formatConsensusBody(collated)
        val sigs = ArrayList<DetachedSignatures.DocumentSignature>()
        for (auth in authorities) {
            sigs += DetachedSignatures.signSha1Rsa(
                body,
                identityFingerprintHex = auth.identityFingerprint.toHex(),
                signingKeyDigestHex = auth.signingKeyDigest.toHex(),
                signingPrivateKey = auth.signing.private,
            )
            if (stopAtQuorum &&
                DirAuthQuorum.hasQuorum(sigs.map { it.identityHex }, knownFingerprints)
            ) {
                break
            }
        }
        val attached = DetachedSignatures.attachToConsensus(body, sigs)
        val detached = DetachedSignatures.formatDetached(
            body,
            validAfter,
            validAfter,
            validAfter,
            sigs,
        )
        val quorum = DirAuthQuorum.hasQuorum(sigs.map { it.identityHex }, knownFingerprints)
        if (dataDir != null) {
            Files.createDirectories(dataDir)
            Files.writeString(dataDir.resolve("cached-consensus"), attached)
            Files.writeString(dataDir.resolve("cached-consensus-diff"), detached)
        }
        return Result(body, attached, detached, sigs.size, quorum)
    }

    /** Merge additional detached signature documents into one. */
    fun mergeDetached(parts: List<String>): DetachedSignatures.Detached {
        val all = parts.map { DetachedSignatures.parse(it) }
        val first = all.first()
        val sigs = all.flatMap { it.signatures }
            .distinctBy { it.identityHex.lowercase() + it.signingKeyDigestHex.lowercase() }
        return DetachedSignatures.Detached(
            validAfter = first.validAfter,
            freshUntil = first.freshUntil,
            validUntil = first.validUntil,
            digests = first.digests,
            signatures = sigs,
        )
    }
}

private fun ByteArray.toHex(): String =
    joinToString("") { b -> "%02x".format(b) }
