package org.kotlintor.path

import java.util.concurrent.ConcurrentHashMap

/**
 * Entry guard reachability / confirmation FSM (C Tor `entry_guard_t`).
 *
 * Complements [GuardEntry] persistence in [PathSelector] with runtime reachability
 * and retry scheduling matching GUARD_REACHABLE_{NO,YES,MAYBE}.
 */
enum class GuardReachable {
    NO,
    YES,
    MAYBE,
}

data class EntryGuardRuntime(
    val fingerprintHex: String,
    var reachable: GuardReachable = GuardReachable.MAYBE,
    var isPending: Boolean = false,
    var lastAttemptEpochSec: Long = 0,
    var lastSuccessEpochSec: Long = 0,
    var confirmed: Boolean = false,
    var confirmedAtEpochSec: Long = 0,
    var failingSinceEpochSec: Long = 0,
    var pathBiasDisabled: Boolean = false,
    var pathbias: GuardPathbiasState = GuardPathbiasState(),
)

class EntryGuardFsm(
    private val retryIntervalSec: Long = 600,
) {
    private val byFp = ConcurrentHashMap<String, EntryGuardRuntime>()

    fun getOrCreate(fp: String): EntryGuardRuntime =
        byFp.getOrPut(fp.lowercase()) { EntryGuardRuntime(fp.lowercase()) }

    fun noteAttempt(fp: String, nowEpochSec: Long = System.currentTimeMillis() / 1000) {
        val g = getOrCreate(fp)
        g.isPending = true
        g.lastAttemptEpochSec = nowEpochSec
    }

    fun noteSuccess(fp: String, nowEpochSec: Long = System.currentTimeMillis() / 1000) {
        val g = getOrCreate(fp)
        g.isPending = false
        g.reachable = GuardReachable.YES
        g.lastSuccessEpochSec = nowEpochSec
        g.failingSinceEpochSec = 0
        if (!g.confirmed) {
            g.confirmed = true
            g.confirmedAtEpochSec = nowEpochSec
        }
    }

    fun noteFailure(fp: String, nowEpochSec: Long = System.currentTimeMillis() / 1000) {
        val g = getOrCreate(fp)
        g.isPending = false
        g.reachable = GuardReachable.NO
        if (g.failingSinceEpochSec == 0L) g.failingSinceEpochSec = nowEpochSec
    }

    fun considerRetry(fp: String, nowEpochSec: Long = System.currentTimeMillis() / 1000): Boolean {
        val g = getOrCreate(fp)
        if (g.pathBiasDisabled) return false
        if (g.reachable == GuardReachable.YES) return false
        if (g.isPending) return false
        return nowEpochSec - g.lastAttemptEpochSec >= retryIntervalSec
    }

    /** Prefer confirmed YES, then MAYBE, never pathbias-disabled. */
    fun pickPreferred(candidates: List<String>): String? {
        val runtimes = candidates.map { getOrCreate(it) }.filter { !it.pathBiasDisabled }
        return runtimes.firstOrNull { it.confirmed && it.reachable == GuardReachable.YES }?.fingerprintHex
            ?: runtimes.firstOrNull { it.reachable == GuardReachable.YES }?.fingerprintHex
            ?: runtimes.firstOrNull { it.reachable == GuardReachable.MAYBE }?.fingerprintHex
            ?: runtimes.firstOrNull()?.fingerprintHex
    }

    fun disableForPathBias(fp: String) {
        getOrCreate(fp).pathBiasDisabled = true
    }

    fun all(): Collection<EntryGuardRuntime> = byFp.values
}
