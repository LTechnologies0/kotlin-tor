package org.kotlintor.dir

import java.util.concurrent.ConcurrentHashMap

/**
 * Guard fraction file parser (C Tor `guardfraction.c`).
 *
 * Format:
 * ```
 * guardfraction-file-version 1
 * written-at YYYY-MM-DD HH:MM:SS
 * n-inputs <consensuses> <days>
 * guard-seen <fpr40> <pct0-100> <appearances>
 * ```
 */
object GuardFraction {
    data class Entry(
        val identityHex: String,
        val percentage: Int,
        val appearances: Int,
    )

    data class File(
        val version: Int,
        val writtenAt: String?,
        val nConsensuses: Int,
        val nDays: Int,
        val guards: List<Entry>,
    )

    fun parse(text: String): File {
        var version = 0
        var writtenAt: String? = null
        var nCons = 0
        var nDays = 0
        val guards = ArrayList<Entry>()
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            val sp = line.split(Regex("\\s+"))
            when (sp[0]) {
                "guardfraction-file-version" ->
                    version = sp.getOrNull(1)?.toIntOrNull() ?: error("bad version")
                "written-at" ->
                    writtenAt = sp.drop(1).joinToString(" ")
                "n-inputs" -> {
                    nCons = sp.getOrNull(1)?.toIntOrNull() ?: 0
                    nDays = sp.getOrNull(2)?.toIntOrNull() ?: 0
                }
                "guard-seen" -> {
                    require(sp.size >= 4) { "bad guard-seen line" }
                    val fp = sp[1].lowercase()
                    require(fp.length == 40 && fp.all { it in "0123456789abcdef" }) {
                        "bad digest $fp"
                    }
                    val pct = sp[2].toInt()
                    require(pct in 0..100) { "pct out of range" }
                    guards += Entry(fp, pct, sp[3].toInt())
                }
            }
        }
        require(version == 1) { "unsupported guardfraction version $version" }
        return File(version, writtenAt, nCons, nDays, guards)
    }

    /**
     * Apply percentages onto [votePercentages] for known identities.
     * When [onlyKnown] is true, skip digests not already present in the map.
     */
    fun applyTo(
        votePercentages: MutableMap<String, Int>,
        file: File,
        onlyKnown: Boolean = false,
    ): Int {
        var n = 0
        for (g in file.guards) {
            if (onlyKnown && !votePercentages.containsKey(g.identityHex)) continue
            votePercentages[g.identityHex] = g.percentage
            n++
        }
        return n
    }
}

/**
 * Directory authority reachability testing (C Tor `reachability.c` lite).
 *
 * Tracks last successful OR TLS per relay; schedules tests by id-modulo buckets.
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
