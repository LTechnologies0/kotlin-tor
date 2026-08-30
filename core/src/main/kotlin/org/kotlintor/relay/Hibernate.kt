package org.kotlintor.relay

/**
 * Bandwidth accounting / hibernation (C Tor `hibernate.c`).
 *
 * Inventory: `L1:feature/hibernate/hibernate.c`
 */
object Hibernate {
    fun accounting(soft: Long = 0, hard: Long = 0, intervalSec: Long = 30 * 24 * 3600): HibernateAccounting =
        HibernateAccounting(soft, hard, intervalSec)
}

class HibernateAccounting(
    var softLimitBytes: Long = 0,
    var hardLimitBytes: Long = 0,
    var intervalSec: Long = 30 * 24 * 3600,
) {
    enum class State { LIVE, SOFT, HARD }

    var bytesRead: Long = 0
        private set
    var bytesWritten: Long = 0
        private set
    var intervalStartedEpochSec: Long = System.currentTimeMillis() / 1000
        private set

    fun note(read: Long = 0, written: Long = 0) {
        bytesRead += read.coerceAtLeast(0)
        bytesWritten += written.coerceAtLeast(0)
    }

    fun total(): Long = bytesRead + bytesWritten

    fun state(nowEpochSec: Long = System.currentTimeMillis() / 1000): State {
        maybeReset(nowEpochSec)
        val t = total()
        if (hardLimitBytes > 0 && t >= hardLimitBytes) return State.HARD
        if (softLimitBytes > 0 && t >= softLimitBytes) return State.SOFT
        return State.LIVE
    }

    fun acceptsNewConnections(nowEpochSec: Long = System.currentTimeMillis() / 1000): Boolean =
        state(nowEpochSec) == State.LIVE

    fun acceptsData(nowEpochSec: Long = System.currentTimeMillis() / 1000): Boolean =
        state(nowEpochSec) != State.HARD

    private fun maybeReset(now: Long) {
        if (intervalSec <= 0) return
        if (now - intervalStartedEpochSec >= intervalSec) {
            bytesRead = 0
            bytesWritten = 0
            intervalStartedEpochSec = now
        }
    }
}
