package org.kotlintor.dir

import org.kotlintor.util.toHex

/**
 * Directory authority voting schedule + act loop (C Tor `voting_schedule.h` /
 * `dirvote_act` in `dirvote.c`).
 *
 * Signing: [DirVoteActor.publishSigned] (Ed25519 testing) and
 * [DirVoteActor.publishSignedRsa] (authority cert signing key / sha1 PKCS1).
 */
object DirVote {
    const val MIN_VOTE_SECONDS: Int = 2
    const val MIN_DIST_SECONDS: Int = 2
    const val MIN_VOTE_INTERVAL: Int = 300
    const val MIN_VOTE_INTERVAL_TESTING: Int = (MIN_VOTE_SECONDS + MIN_DIST_SECONDS + 1) * 2
    const val MIN_SUPPORTED_CONSENSUS_METHOD: Int = 32
    const val MAX_SUPPORTED_CONSENSUS_METHOD: Int = 35
    const val DEFAULT_MAX_UNMEASURED_BW_KB: Int = 20

    const val DGV_BY_ID: Int = 1
    const val DGV_INCLUDE_PENDING: Int = 2
    const val DGV_INCLUDE_PREVIOUS: Int = 4

    /** C Tor `DIRVOTE_UNIVERSAL_FLAGS` subset used in votes. */
    val UNIVERSAL_FLAGS: List<String> =
        listOf("Authority", "BadExit", "Exit", "Fast", "Guard", "HSDir", "NoEdConsensus", "Stable", "StaleDesc", "Running", "Valid", "V2Dir")

    data class Timing(
        val voteIntervalSec: Int,
        val voteSeconds: Int,
        val distSeconds: Int,
        val testing: Boolean = false,
    ) {
        init {
            val minInterval = if (testing) MIN_VOTE_INTERVAL_TESTING else MIN_VOTE_INTERVAL
            require(voteIntervalSec >= minInterval) {
                "voteInterval $voteIntervalSec < min $minInterval"
            }
            require(voteSeconds >= MIN_VOTE_SECONDS)
            require(distSeconds >= MIN_DIST_SECONDS)
            require(voteSeconds + distSeconds < voteIntervalSec) {
                "voteSeconds+distSeconds must fit in voteInterval"
            }
        }
    }

    data class Schedule(
        val votingStarts: Long,
        val fetchMissingVotes: Long,
        val votingEnds: Long,
        val fetchMissingSignatures: Long,
        val intervalStarts: Long,
        val interval: Int,
        var haveVoted: Boolean = false,
        var haveFetchedMissingVotes: Boolean = false,
        var haveBuiltConsensus: Boolean = false,
        var haveFetchedMissingSignatures: Boolean = false,
        var havePublishedConsensus: Boolean = false,
        var createdOnDemand: Boolean = false,
        var liveConsensusValidAfter: Long = 0,
    )

    enum class Phase {
        VOTE,
        FETCH_VOTES,
        COMPUTE_CONSENSUS,
        FETCH_SIGNATURES,
        PUBLISH,
        IDLE,
    }

    /**
     * Build schedule for interval starting at [intervalStarts] (valid-after).
     * Layout matches C Tor: vote at valid-after − voteSeconds − distSeconds, etc.
     */
    fun buildSchedule(timing: Timing, intervalStartsEpochSec: Long): Schedule {
        val voteAt = intervalStartsEpochSec - timing.distSeconds - timing.voteSeconds
        val fetchVotesAt = intervalStartsEpochSec - timing.distSeconds
        val votingEnds = fetchVotesAt // compute consensus when dist window opens
        val fetchSigsAt = intervalStartsEpochSec - (timing.distSeconds / 2).coerceAtLeast(1)
        return Schedule(
            votingStarts = voteAt,
            fetchMissingVotes = fetchVotesAt,
            votingEnds = votingEnds,
            fetchMissingSignatures = fetchSigsAt,
            intervalStarts = intervalStartsEpochSec,
            interval = timing.voteIntervalSec,
        )
    }

    /** Next valid-after after [now], aligned to [timing.voteIntervalSec] from epoch. */
    fun nextValidAfter(timing: Timing, nowEpochSec: Long): Long {
        val i = timing.voteIntervalSec.toLong()
        val aligned = ((nowEpochSec / i) + 1) * i
        return aligned
    }

    fun preferredConsensusMethod(votes: List<Int>): Int {
        val supported = votes.filter { it in MIN_SUPPORTED_CONSENSUS_METHOD..MAX_SUPPORTED_CONSENSUS_METHOD }
        if (supported.isEmpty()) return MIN_SUPPORTED_CONSENSUS_METHOD
        // Majority floor among advertised methods (simplified compute_consensus_method).
        val counts = supported.groupingBy { it }.eachCount()
        val majority = (votes.size + 1) / 2
        return counts.filter { it.value >= majority }.keys.maxOrNull()
            ?: supported.maxOrNull()!!
    }
}

/**
 * Mutable dirvote actor — mirrors `dirvote_act` phase transitions.
 */
class DirVoteActor(
    private var timing: DirVote.Timing,
    private var schedule: DirVote.Schedule,
    private val onVote: () -> Unit = {},
    private val onFetchVotes: () -> Unit = {},
    private val onComputeConsensus: () -> Unit = {},
    private val onFetchSignatures: () -> Unit = {},
    private val onPublish: () -> Unit = {},
    val keypin: Keypin.Journal = Keypin.Journal(),
    val consCache: ConsCache = ConsCache(),
    val reachability: ReachabilityTracker = ReachabilityTracker(),
    val guardFractions: MutableMap<String, Int> = LinkedHashMap(),
    val processDescs: ProcessDescs = ProcessDescs(),
    val authMode: AuthModeOptions = AuthModeOptions(authoring = true),
    val consDiffMgr: ConsDiffMgr = ConsDiffMgr(),
) {
    fun recalculate(nowEpochSec: Long) {
        val next = DirVote.nextValidAfter(timing, nowEpochSec)
        schedule = DirVote.buildSchedule(timing, next).copy(createdOnDemand = false)
    }

    /**
     * Advance schedule; returns epoch seconds of next wake (or [Long.MAX_VALUE] if idle).
     */
    fun act(nowEpochSec: Long): Long {
        if (schedule.createdOnDemand) recalculate(nowEpochSec)

        fun step(whenField: Long, done: Boolean, mark: () -> Unit, action: () -> Unit): Long? {
            if (done) return null
            if (whenField > nowEpochSec) return whenField
            action()
            mark()
            return null
        }

        step(schedule.votingStarts, schedule.haveVoted, { schedule.haveVoted = true }, onVote)
            ?.let { return it }
        step(schedule.fetchMissingVotes, schedule.haveFetchedMissingVotes, {
            schedule.haveFetchedMissingVotes = true
        }, onFetchVotes)?.let { return it }
        step(schedule.votingEnds, schedule.haveBuiltConsensus, {
            schedule.haveBuiltConsensus = true
        }, onComputeConsensus)?.let { return it }
        step(schedule.fetchMissingSignatures, schedule.haveFetchedMissingSignatures, {
            schedule.haveFetchedMissingSignatures = true
        }, onFetchSignatures)?.let { return it }
        step(schedule.intervalStarts, schedule.havePublishedConsensus, {
            schedule.havePublishedConsensus = true
        }, onPublish)?.let { return it }

        // Roll to next interval.
        val nextStart = schedule.intervalStarts + schedule.interval
        schedule = DirVote.buildSchedule(timing, nextStart)
        return schedule.votingStarts
    }

    fun currentPhase(nowEpochSec: Long): DirVote.Phase = when {
        !schedule.haveVoted && nowEpochSec >= schedule.votingStarts -> DirVote.Phase.VOTE
        !schedule.haveFetchedMissingVotes && nowEpochSec >= schedule.fetchMissingVotes ->
            DirVote.Phase.FETCH_VOTES
        !schedule.haveBuiltConsensus && nowEpochSec >= schedule.votingEnds ->
            DirVote.Phase.COMPUTE_CONSENSUS
        !schedule.haveFetchedMissingSignatures && nowEpochSec >= schedule.fetchMissingSignatures ->
            DirVote.Phase.FETCH_SIGNATURES
        !schedule.havePublishedConsensus && nowEpochSec >= schedule.intervalStarts ->
            DirVote.Phase.PUBLISH
        else -> DirVote.Phase.IDLE
    }

    fun pendingVotes(): Map<String, BandwidthVote.VoteDocument> = LinkedHashMap(votes)

    private val votes = LinkedHashMap<String, BandwidthVote.VoteDocument>()

    fun addVote(body: String, from: String = "local"): BandwidthVote.VoteDocument {
        val doc = BandwidthVote.parse(body)
        for (r in doc.routers) {
            val rsaTok = r.identityHex
            val ed = r.ed25519IdentityHex
            // Keypin expects raw SHA1 digests; only apply when identity looks like hex40.
            if (rsaTok != null && ed != null &&
                rsaTok.length == 40 && rsaTok.all { it in "0123456789abcdefABCDEF" } &&
                ed.length == 64 && ed.all { it in "0123456789abcdefABCDEF" }
            ) {
                runCatching {
                    fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                    keypin.checkAndAdd(hex(rsaTok), hex(ed))
                }
            }
            if (rsaTok != null && r.ip != null && r.orPort != null) {
                reachability.noteTarget(
                    ReachabilityTracker.Target(
                        identityHex = rsaTok.lowercase(),
                        ip = r.ip,
                        orPort = r.orPort,
                        ed25519Hex = ed,
                    ),
                )
            }
        }
        val id = doc.header.published ?: from
        votes[id + ":" + (doc.routers.firstOrNull()?.identityHex ?: from)] = doc
        return doc
    }

    fun loadGuardFractionFile(text: String): Int {
        val file = GuardFraction.parse(text)
        return GuardFraction.applyTo(guardFractions, file)
    }

    fun computeConsensusBody(nAuthorities: Int = votes.size): String {
        val collated = DirCollator.collate(votes.values.toList(), nAuthorities)
        val body = DirCollator.formatConsensusBody(collated)
        consCache.put(body)
        return body
    }

    /**
     * Sign [computeConsensusBody] with Ed25519 testing keys and emit detached + attached forms.
     */
    fun publishSigned(
        identityHex: String,
        privateKey: ByteArray,
        validAfter: String = "2020-01-01 00:00:00",
    ): Pair<String, String> {
        val body = computeConsensusBody()
        val sig = DetachedSignatures.signEd25519(body, identityHex, privateKey)
        val attached = DetachedSignatures.attachToConsensus(body, listOf(sig))
        val detached = DetachedSignatures.formatDetached(
            body,
            validAfter,
            validAfter,
            validAfter,
            listOf(sig),
        )
        return attached to detached
    }

    /**
     * Sign consensus with RSA authority cert signing key (dir-spec sha1 signature).
     */
    fun publishSignedRsa(
        authority: AuthorityCert.Material,
        sharedRandom: SharedRandom.Srv? = null,
        validAfter: String = "2020-01-01 00:00:00",
    ): Pair<String, String> {
        val collated = DirCollator.collate(votes.values.toList(), votes.size)
        val body = DirCollator.formatConsensusBody(collated, sharedRandom = sharedRandom)
        val sig = DetachedSignatures.signSha1Rsa(
            body,
            identityFingerprintHex = authority.identityFingerprint.toHex(),
            signingKeyDigestHex = authority.signingKeyDigest.toHex(),
            signingPrivateKey = authority.signing.private,
        )
        val attached = DetachedSignatures.attachToConsensus(body, listOf(sig))
        val detached = DetachedSignatures.formatDetached(
            body,
            validAfter,
            validAfter,
            validAfter,
            listOf(sig),
        )
        return attached to detached
    }
}
