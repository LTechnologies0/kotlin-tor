package org.kotlintor.hs

import java.time.Duration
import java.time.Instant

/**
 * Onion-service time period (rend-spec-v3 TIME-PERIODS).
 * Default length 1440 minutes; epoch offset 12 voting periods (12h when voting=1h).
 */
data class HsTimePeriod(
    val intervalNum: Long,
    val lengthMinutes: Long = DEFAULT_LENGTH_MINUTES,
    val epochOffsetSeconds: Long = DEFAULT_EPOCH_OFFSET_SECONDS,
) {
    companion object {
        const val DEFAULT_LENGTH_MINUTES: Long = 1440
        const val DEFAULT_EPOCH_OFFSET_SECONDS: Long = 12 * 60 * 60

        fun containing(
            whenInstant: Instant,
            lengthMinutes: Long = DEFAULT_LENGTH_MINUTES,
            epochOffset: Duration = Duration.ofSeconds(DEFAULT_EPOCH_OFFSET_SECONDS),
        ): HsTimePeriod {
            require(lengthMinutes > 0)
            val lengthSec = lengthMinutes * 60
            val since = whenInstant.epochSecond - epochOffset.seconds
            require(since >= 0) { "time before HS epoch" }
            return HsTimePeriod(since / lengthSec, lengthMinutes, epochOffset.seconds)
        }
    }
}
