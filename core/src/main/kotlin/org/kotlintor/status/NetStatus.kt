package org.kotlintor.status

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Network disable / dormant participation tracking (C Tor `netstatus.c`).
 *
 * Inventory: `L1:core/mainloop/netstatus.c`
 */
object NetStatus {
    data class Options(
        val disableNetwork: Boolean = false,
        val dormantOnFirstStartup: Boolean = false,
        val dormantCanceledByStartup: Boolean = false,
        val dormantTimeoutEnabled: Boolean = true,
    )

    data class MainloopState(
        /** -1 = unset (initial); 0 = participating; 1 = dormant. */
        var dormant: Int = -1,
        var minutesSinceUserActivity: Int = 0,
    )

    @Volatile
    var options: Options = Options()

    /** Soft hibernate (entering) — C Tor `we_are_hibernating`. */
    @Volatile
    var hibernating: Boolean = false

    /** Hard hibernate — C Tor `we_are_fully_hibernating`. */
    @Volatile
    var fullyHibernating: Boolean = false

    private val lastUserActivityEpochSec = AtomicLong(0)
    private val participating = AtomicBoolean(false)

    /** C Tor `net_is_disabled`. */
    fun netIsDisabled(): Boolean =
        options.disableNetwork || hibernating

    /** C Tor `net_is_completely_disabled`. */
    fun netIsCompletelyDisabled(): Boolean =
        options.disableNetwork || fullyHibernating

    /** C Tor `note_user_activity`. */
    fun noteUserActivity(nowEpochSec: Long = System.currentTimeMillis() / 1000L) {
        val prev = lastUserActivityEpochSec.get()
        if (nowEpochSec > prev) lastUserActivityEpochSec.set(nowEpochSec)
        if (!participating.get()) {
            setNetworkParticipation(true)
        }
    }

    /** C Tor `reset_user_activity`. */
    fun resetUserActivity(nowEpochSec: Long) {
        lastUserActivityEpochSec.set(nowEpochSec)
    }

    /** C Tor `get_last_user_activity_time`. */
    fun lastUserActivityTime(): Long = lastUserActivityEpochSec.get()

    fun setNetworkParticipation(participation: Boolean) {
        participating.set(participation)
    }

    fun isParticipatingOnNetwork(): Boolean = participating.get()

    /** C Tor `netstatus_flush_to_state`. */
    fun flushToState(state: MainloopState, nowEpochSec: Long = System.currentTimeMillis() / 1000L) {
        state.dormant = if (participating.get()) 0 else 1
        if (participating.get()) {
            val sec = (nowEpochSec - lastUserActivityEpochSec.get()).coerceAtLeast(0)
            state.minutesSinceUserActivity = (sec / 60).toInt()
        } else {
            state.minutesSinceUserActivity = 0
        }
    }

    /** C Tor `netstatus_load_from_state`. */
    fun loadFromState(state: MainloopState, nowEpochSec: Long = System.currentTimeMillis() / 1000L) {
        var lastActivity: Long
        var part: Boolean
        when {
            state.dormant == -1 -> {
                if (options.dormantOnFirstStartup) {
                    lastActivity = 0
                    part = false
                } else {
                    lastActivity = nowEpochSec
                    part = true
                }
            }
            state.dormant != 0 -> {
                lastActivity = 0
                part = false
            }
            else -> {
                lastActivity = nowEpochSec - 60L * state.minutesSinceUserActivity
                part = true
            }
        }
        if (options.dormantCanceledByStartup) {
            lastActivity = nowEpochSec
            part = true
        }
        if (!options.dormantTimeoutEnabled) {
            part = true
        }
        participating.set(part)
        resetUserActivity(lastActivity)
    }

    /** C Tor `netstatus_note_clock_jumped`. */
    fun noteClockJumped(secondsDiff: Long) {
        val last = lastUserActivityTime()
        if (last != 0L) resetUserActivity(last + secondsDiff)
    }

    fun resetForTests() {
        options = Options()
        hibernating = false
        fullyHibernating = false
        lastUserActivityEpochSec.set(0)
        participating.set(false)
    }
}
