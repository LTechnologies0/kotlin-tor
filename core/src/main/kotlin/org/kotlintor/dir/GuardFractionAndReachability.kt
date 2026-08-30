package org.kotlintor.dir

import java.util.concurrent.ConcurrentHashMap

/**
 * Directory authority reachability testing (C Tor `reachability.c`).
 *
 * Inventory: `L1:feature/dirauth/reachability.c`
 *
 * Tracks last successful OR TLS per relay; schedules tests by id-modulo buckets.
 * Naming facade: [Reachability].
 */
class ReachabilityTracker(
    private val moduloPerTest: Int = REACHABILITY_MODULO_PER_TEST,
    private val testIntervalSec: Long = REACHABILITY_TEST_INTERVAL_SEC,
) {
    data class Target(
        val identityHex: String,
        val ip: String,
        val orPort: Int,
        val ed25519Hex: String? = null,
        val hibernating: Boolean = false,
    )

    data class Status(
        var lastReachableEpochSec: Long = 0,
        var lastTestAttemptEpochSec: Long = 0,
        var reachable: Boolean = false,
        var pending: Boolean = false,
    )

    private val byId = ConcurrentHashMap<String, Status>()
    private val targets = ConcurrentHashMap<String, Target>()

    fun noteTarget(t: Target) {
        targets[t.identityHex.lowercase()] = t
        byId.putIfAbsent(t.identityHex.lowercase(), Status())
    }

    fun shouldLaunchTest(newRi: Target, oldRi: Target?): Boolean {
        if (oldRi == null) return true
        if (oldRi.hibernating && !newRi.hibernating) return true
        if (oldRi.ip != newRi.ip || oldRi.orPort != newRi.orPort) return true
        return false
    }

    fun noteTlsDone(
        identityHex: String,
        addr: String,
        orPort: Int,
        ed25519Hex: String? = null,
        nowEpochSec: Long = System.currentTimeMillis() / 1000,
    ): Boolean {
        val id = identityHex.lowercase()
        val t = targets[id] ?: return false
        if (t.ip != addr || t.orPort != orPort) return false
        if (t.ed25519Hex != null && ed25519Hex != null &&
            !t.ed25519Hex.equals(ed25519Hex, ignoreCase = true)
        ) {
            return false
        }
        val st = byId.getOrPut(id) { Status() }
        st.lastReachableEpochSec = nowEpochSec
        st.reachable = true
        st.pending = false
        return true
    }

    /**
     * Relays whose fingerprint hash % [moduloPerTest] == [bucket] and due for a test.
     */
    fun dueForTest(
        nowEpochSec: Long,
        bucket: Int = ((nowEpochSec / testIntervalSec) % moduloPerTest).toInt(),
    ): List<Target> {
        val out = ArrayList<Target>()
        for ((id, t) in targets) {
            val dig = id.hashCode().and(0x7fff_ffff) % moduloPerTest
            if (dig != bucket) continue
            val st = byId.getOrPut(id) { Status() }
            if (st.pending) continue
            if (nowEpochSec - st.lastTestAttemptEpochSec < testIntervalSec) continue
            st.lastTestAttemptEpochSec = nowEpochSec
            st.pending = true
            out += t
        }
        return out
    }

    fun markTestFailed(identityHex: String) {
        byId[identityHex.lowercase()]?.let {
            it.pending = false
            it.reachable = false
        }
    }

    fun isReachable(identityHex: String): Boolean =
        byId[identityHex.lowercase()]?.reachable == true

    fun status(identityHex: String): Status? = byId[identityHex.lowercase()]

    companion object {
        const val REACHABILITY_MODULO_PER_TEST: Int = 128
        const val REACHABILITY_TEST_INTERVAL_SEC: Long = 10
        const val REACHABILITY_TEST_CYCLE_PERIOD_SEC: Long =
            REACHABILITY_TEST_INTERVAL_SEC * REACHABILITY_MODULO_PER_TEST
    }
}
