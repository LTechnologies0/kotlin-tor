package org.kotlintor.dir

/**
 * Directory download status / exponential backoff (C Tor `dlstatus.c` / `download_status_t`).
 *
 * Inventory: `L1:feature/dirclient/dlstatus.c`, `L2:core/or/download_status_t`
 */
class DownloadStatus(
    private val minDelaySec: Int = 10,
    private val maxDelaySec: Int = 3600,
    private val multiplier: Int = DIR_DEFAULT_RANDOM_MULTIPLIER,
) {
    var nFailures: Int = 0
        private set
    var nAttempts: Int = 0
        private set
    var nextAttemptAt: Long = 0
        private set
    var impossible: Boolean = false
        private set
    private var lastDelaySec: Int = minDelaySec

    fun reset() {
        nFailures = 0
        nAttempts = 0
        nextAttemptAt = 0
        impossible = false
        lastDelaySec = minDelaySec
    }

    fun markImpossible() {
        impossible = true
        nextAttemptAt = Long.MAX_VALUE / 4
    }

    fun isReady(nowEpochSec: Long = System.currentTimeMillis() / 1000): Boolean =
        !impossible && nowEpochSec >= nextAttemptAt

    fun incrementAttempt(nowEpochSec: Long = System.currentTimeMillis() / 1000): Long {
        nAttempts++
        return schedule(nowEpochSec)
    }

    fun incrementFailure(nowEpochSec: Long = System.currentTimeMillis() / 1000): Long {
        nFailures++
        return schedule(nowEpochSec)
    }

    private fun schedule(now: Long): Long {
        val high = (lastDelaySec * (multiplier + 1)).coerceAtMost(maxDelaySec)
        val low = lastDelaySec.coerceAtLeast(minDelaySec)
        val delay = if (high <= low) low else low + org.kotlintor.util.SecureRandomSource.nextInt(high - low + 1)
        lastDelaySec = delay.coerceIn(minDelaySec, maxDelaySec)
        nextAttemptAt = now + lastDelaySec
        return nextAttemptAt
    }

    companion object {
        const val DIR_DEFAULT_RANDOM_MULTIPLIER: Int = 3
        const val DIR_TEST_NET_RANDOM_MULTIPLIER: Int = 2
    }
}
