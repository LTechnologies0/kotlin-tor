package org.kotlintor.dir

/**
 * Voting schedule (C Tor `voting_schedule.c` / `voting_schedule_t`).
 *
 * Computes interval start, voting / dist deadlines from consensus timing
 * or testing defaults.
 *
 * Inventory: `L1:feature/dirauth/voting_schedule.c`
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

        /** Mutable global schedule used by dirauth_sched_* aliases. */
        @Volatile
        private var active: VotingSchedule? = null

        @Volatile
        private var configuredIntervalSec: Int = 300

        /** C Tor `dirauth_sched_recalculate_timing`. */
        fun dirauthSchedRecalculateTiming(
            nowEpochSec: Long,
            intervalSec: Int = 300,
            voteDelaySec: Int = 20,
            distDelaySec: Int = 20,
        ): VotingSchedule {
            configuredIntervalSec = intervalSec
            val sched = create(nowEpochSec, intervalSec, voteDelaySec, distDelaySec)
            active = sched
            return sched
        }

        /** C Tor `dirauth_sched_get_configured_interval`. */
        fun dirauthSchedGetConfiguredInterval(): Int = configuredIntervalSec

        /** C Tor `dirauth_sched_get_cur_valid_after_time`. */
        fun dirauthSchedGetCurValidAfterTime(): Long =
            active?.intervalStartsEpochSec ?: 0L

        /** C Tor `dirauth_sched_get_next_valid_after_time`. */
        fun dirauthSchedGetNextValidAfterTime(nowEpochSec: Long = System.currentTimeMillis() / 1000): Long {
            val cur = active
            return if (cur != null && nowEpochSec < cur.intervalEndsEpochSec) {
                cur.intervalEndsEpochSec
            } else {
                startOfIntervalAfter(nowEpochSec, configuredIntervalSec)
            }
        }
    }
}
