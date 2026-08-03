package org.kotlintor.dir

/**
 * Voting schedule (C Tor `voting_schedule.c` / `voting_schedule_t`).
 *
 * Computes interval start, voting / dist deadlines from consensus timing
 * or testing defaults.
 */
data class VotingSchedule(
    val intervalSec: Int,
    val voteDelaySec: Int,
    val distDelaySec: Int,
    val intervalStartsEpochSec: Long,
    val votingStartsEpochSec: Long,
    val votingEndsEpochSec: Long,
    val fetchingStartsEpochSec: Long,
    val intervalEndsEpochSec: Long,
    val liveConsensusValidAfter: Long = 0,
) {
    fun phaseAt(nowEpochSec: Long): Phase = when {
        nowEpochSec < votingStartsEpochSec -> Phase.IDLE
        nowEpochSec < votingEndsEpochSec -> Phase.VOTING
        nowEpochSec < fetchingStartsEpochSec -> Phase.DIST
        nowEpochSec < intervalEndsEpochSec -> Phase.FETCHING
        else -> Phase.IDLE
    }

    enum class Phase { IDLE, VOTING, DIST, FETCHING }

    companion object {
        fun create(
            nowEpochSec: Long,
            intervalSec: Int = 300,
            voteDelaySec: Int = 20,
            distDelaySec: Int = 20,
            votingStartOffsetSec: Int = 0,
            liveConsensusValidAfter: Long = 0,
        ): VotingSchedule {
            var vote = voteDelaySec
            var dist = distDelaySec
            if (vote + dist > intervalSec / 2) {
                vote = intervalSec / 4
                dist = intervalSec / 4
            }
            val start = startOfIntervalAfter(nowEpochSec, intervalSec, votingStartOffsetSec)
            val votingStarts = start - vote - dist
            val votingEnds = start - dist
            val fetchingStarts = start
            val intervalEnds = start + intervalSec
            return VotingSchedule(
                intervalSec = intervalSec,
                voteDelaySec = vote,
                distDelaySec = dist,
                intervalStartsEpochSec = start,
                votingStartsEpochSec = votingStarts,
                votingEndsEpochSec = votingEnds,
                fetchingStartsEpochSec = fetchingStarts,
                intervalEndsEpochSec = intervalEnds,
                liveConsensusValidAfter = liveConsensusValidAfter,
            )
        }

        /** Next aligned interval boundary after [now] (C Tor `voting_sched_get_start_of_interval_after`). */
        fun startOfIntervalAfter(nowEpochSec: Long, intervalSec: Int, offsetSec: Int = 0): Long {
            require(intervalSec > 0)
            val adjusted = nowEpochSec - offsetSec
            val next = ((adjusted / intervalSec) + 1) * intervalSec + offsetSec
            return next
        }
    }
}

/**
 * Multi-authority network coordinator: N [DirAuthPublishLoop] peers exchange
 * votes until [DirAuthQuorum] is met (local TestingTorNetwork style).
 */
class MultiAuthNetwork(
    private val peers: List<DirAuthPublishLoop>,
) {
    init {
        require(peers.isNotEmpty())
    }

    fun startAll() = peers.forEach { it.start() }
    fun stopAll() = peers.forEach { it.stop() }

    /** Push [voteBody] from [fromFp] to every peer except the originator. */
    fun gossipVote(voteBody: String, fromFp: String) {
        for (p in peers) {
            p.addPeerVote(voteBody, fromFp)
        }
    }

    fun publishAll(): List<Pair<String, String>> =
        peers.mapNotNull { it.publishNow() }

    fun gossipHttp(
        httpPeers: List<Pair<String, Int>>,
        voteBody: String,
        fromFp: String,
    ): List<DirAuthVoteGossip.Result> {
        return kotlinx.coroutines.runBlocking {
            DirAuthVoteGossip.gossipToPeers(httpPeers, voteBody, fromFp)
        }
    }

    suspend fun gossipHttpSuspend(
        httpPeers: List<Pair<String, Int>>,
        voteBody: String,
        fromFp: String,
    ): List<DirAuthVoteGossip.Result> =
        DirAuthVoteGossip.gossipToPeers(httpPeers, voteBody, fromFp)

    fun quorumSatisfied(detachedBodies: List<String>, known: Set<String>): Boolean {
        val ids = detachedBodies.flatMap { DetachedSignatures.parse(it).signatures.map { s -> s.identityHex } }
        return DirAuthQuorum.hasQuorum(ids, known, known.size.coerceAtLeast(1))
    }
}
