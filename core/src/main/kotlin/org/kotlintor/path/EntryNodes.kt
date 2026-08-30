package org.kotlintor.path

import org.kotlintor.config.TorConfig
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicLong

/**
 * Entry guards / sampled primary set (C Tor `entrynodes.c` / `entrynodes.h`).
 *
 * Inventory: `L1:feature/client/entrynodes.c`
 *
 * Reachability FSM: [EntryGuardFsm] / [EntryGuardRuntime].
 */
object EntryNodes {
    private val selections = ConcurrentHashMap<String, GuardSelection>()
    private val defaultFsm = EntryGuardFsm()
    private val circStateSeq = AtomicLong(1)
    private val bridgeIdentityByAddr = ConcurrentHashMap<String, String>()

    fun useEntryGuards(config: TorConfig): Boolean = config.useEntryGuards

    fun numEntryGuards(config: TorConfig): Int = config.numEntryGuards.coerceIn(1, 16)

    fun newFsm(retryIntervalSec: Long = 600): EntryGuardFsm = EntryGuardFsm(retryIntervalSec)

    fun confirmed(g: EntryGuardRuntime): Boolean = g.confirmed

    fun isReachable(g: EntryGuardRuntime): Boolean = g.reachable == GuardReachable.YES

    /** C Tor `get_guard_selection_info` — default (bridges=false) selection. */
    fun getGuardSelectionInfo(): GuardSelection = guardSelection("default")

    fun guardSelection(name: String): GuardSelection =
        selections.getOrPut(name) { GuardSelection(name) }

    /** C Tor `choose_guard_selection`. */
    fun chooseGuardSelection(config: TorConfig): String {
        val name = when {
            config.useBridges || config.bridges.isNotEmpty() -> "bridges"
            else -> "default"
        }
        guardSelection(name)
        return name
    }

    /** C Tor `entry_guard_add_to_sample`. */
    fun entryGuardAddToSample(gs: GuardSelection, fingerprintHex: String): EntryGuardRuntime {
        val g = gs.fsm.getOrCreate(fingerprintHex)
        if (gs.sampled.none { it.fingerprintHex == g.fingerprintHex }) {
            gs.sampled += g
        }
        return g
    }

    /** C Tor `entry_guard_get_by_id_digest`. */
    fun entryGuardGetByIdDigest(digestHex: String): EntryGuardRuntime? {
        val fp = digestHex.filter { it != ' ' }.lowercase()
        return getGuardSelectionInfo().sampled.firstOrNull { it.fingerprintHex == fp }
            ?: defaultFsm.all().firstOrNull { it.fingerprintHex == fp }
    }

    /** C Tor `entry_guard_get_by_id_digest_for_guard_selection`. */
    fun entryGuardGetByIdDigestForGuardSelection(
        gs: GuardSelection,
        digestHex: String,
    ): EntryGuardRuntime? {
        val fp = digestHex.filter { it != ' ' }.lowercase()
        return gs.sampled.firstOrNull { it.fingerprintHex == fp }
            ?: gs.fsm.all().firstOrNull { it.fingerprintHex == fp }
    }

    /** C Tor `entry_guard_find_node` — returns fingerprint when present in sample. */
    fun entryGuardFindNode(guard: EntryGuardRuntime): String? =
        guard.fingerprintHex.takeIf { it.isNotBlank() }

    /** C Tor `entry_guard_get_rsa_id_digest` — hex identity string. */
    fun entryGuardGetRsaIdDigest(guard: EntryGuardRuntime): String = guard.fingerprintHex

    /** C Tor `entry_guard_describe`. */
    fun entryGuardDescribe(guard: EntryGuardRuntime): String =
        "Guard ${guard.fingerprintHex.take(8)} reachable=${guard.reachable} confirmed=${guard.confirmed}"

    /** C Tor `entry_guard_get_pathbias_state`. */
    fun entryGuardGetPathbiasState(guard: EntryGuardRuntime): GuardPathbiasState =
        guard.pathbias

    /** C Tor `entry_guard_has_higher_priority`. */
    fun entryGuardHasHigherPriority(a: EntryGuardRuntime, b: EntryGuardRuntime): Boolean {
        if (a.confirmed != b.confirmed) return a.confirmed
        if (a.reachable != b.reachable) {
            return a.reachable == GuardReachable.YES && b.reachable != GuardReachable.YES
        }
        return a.confirmedAtEpochSec >= b.confirmedAtEpochSec
    }

    /** C Tor `entry_guard_encode_for_state`. */
    fun entryGuardEncodeForState(guard: EntryGuardRuntime): String =
        listOf(
            guard.fingerprintHex,
            if (guard.confirmed) "1" else "0",
            guard.confirmedAtEpochSec.toString(),
            guard.reachable.name,
            guard.lastAttemptEpochSec.toString(),
            guard.lastSuccessEpochSec.toString(),
        ).joinToString(" ")

    /** C Tor `entry_guard_parse_from_state`. */
    fun entryGuardParseFromState(line: String): EntryGuardRuntime? {
        val parts = line.trim().split(Regex("\\s+"))
        if (parts.isEmpty() || parts[0].length < 8) return null
        val g = EntryGuardRuntime(parts[0].lowercase())
        if (parts.size > 1) g.confirmed = parts[1] == "1"
        if (parts.size > 2) g.confirmedAtEpochSec = parts[2].toLongOrNull() ?: 0
        if (parts.size > 3) {
            g.reachable = runCatching { GuardReachable.valueOf(parts[3]) }.getOrDefault(GuardReachable.MAYBE)
        }
        if (parts.size > 4) g.lastAttemptEpochSec = parts[4].toLongOrNull() ?: 0
        if (parts.size > 5) g.lastSuccessEpochSec = parts[5].toLongOrNull() ?: 0
        return g
    }

    /** C Tor `entry_guard_free_`. */
    fun entryGuardFree_(guard: EntryGuardRuntime?): EntryGuardRuntime? = null

    /** C Tor `entry_guard_restriction_free_`. */
    fun entryGuardRestrictionFree_(rst: EntryGuardRestriction?): EntryGuardRestriction? = null

    /** C Tor `circuit_guard_state_free_`. */
    fun circuitGuardStateFree_(state: CircuitGuardState?): CircuitGuardState? = null

    /** C Tor `entry_guard_consider_retry`. */
    fun entryGuardConsiderRetry(
        guard: EntryGuardRuntime,
        nowEpochSec: Long = System.currentTimeMillis() / 1000,
        retryIntervalSec: Long = 600,
    ): Boolean {
        if (guard.pathBiasDisabled) return false
        if (guard.reachable == GuardReachable.YES) return false
        if (guard.isPending) return false
        return nowEpochSec - guard.lastAttemptEpochSec >= retryIntervalSec
    }

    /** C Tor `entry_guard_pick_for_circuit`. */
    fun entryGuardPickForCircuit(
        gs: GuardSelection,
        rst: EntryGuardRestriction? = null,
    ): Pair<EntryGuardRuntime, CircuitGuardState>? {
        val candidates = gs.sampled.map { it.fingerprintHex }.ifEmpty {
            gs.fsm.all().map { it.fingerprintHex }
        }
        val filtered = candidates.filter { fp ->
            rst == null || !rst.excludedFingerprints.contains(fp.lowercase())
        }
        val picked = gs.fsm.pickPreferred(filtered) ?: return null
        val guard = gs.fsm.getOrCreate(picked)
        gs.fsm.noteAttempt(picked)
        val state = CircuitGuardState(
            id = circStateSeq.getAndIncrement(),
            guardFingerprint = picked,
            state = CircGuardStateKind.WAITING_FOR_BETTER,
            createdEpochSec = System.currentTimeMillis() / 1000,
            restrictions = rst,
        )
        return guard to state
    }

    /** C Tor `entry_guard_succeeded`. */
    fun entryGuardSucceeded(state: CircuitGuardState): GuardUsable {
        defaultFsm.noteSuccess(state.guardFingerprint)
        guardSelection("default").fsm.noteSuccess(state.guardFingerprint)
        state.state = CircGuardStateKind.COMPLETE
        return GuardUsable.NOW
    }

    /** C Tor `entry_guard_failed`. */
    fun entryGuardFailed(state: CircuitGuardState) {
        defaultFsm.noteFailure(state.guardFingerprint)
        guardSelection("default").fsm.noteFailure(state.guardFingerprint)
        state.state = CircGuardStateKind.DEAD
    }

    /** C Tor `entry_guard_cancel`. */
    fun entryGuardCancel(state: CircuitGuardState) {
        state.state = CircGuardStateKind.DEAD
        val g = defaultFsm.getOrCreate(state.guardFingerprint)
        g.isPending = false
    }

    /** C Tor `entry_guard_chan_failed` — mark pending guard unreachable by channel id map. */
    fun entryGuardChanFailed(channelId: Long, fingerprintHex: String?) {
        if (fingerprintHex.isNullOrBlank()) return
        defaultFsm.noteFailure(fingerprintHex)
    }

    /** C Tor `entry_guard_could_succeed`. */
    fun entryGuardCouldSucceed(state: CircuitGuardState): Boolean =
        state.state == CircGuardStateKind.WAITING_FOR_BETTER ||
            state.state == CircGuardStateKind.COMPLETE

    /** C Tor `entry_guard_state_should_expire`. */
    fun entryGuardStateShouldExpire(
        state: CircuitGuardState,
        nowEpochSec: Long = System.currentTimeMillis() / 1000,
        ttlSec: Long = 600,
    ): Boolean = nowEpochSec - state.createdEpochSec >= ttlSec

    /** C Tor `entry_guard_learned_bridge_identity`. */
    fun entryGuardLearnedBridgeIdentity(host: String, port: Int, fingerprintHex: String) {
        val key = "${host.lowercase()}:$port"
        bridgeIdentityByAddr[key] = fingerprintHex.filter { it != ' ' }.lowercase()
        entryGuardAddToSample(guardSelection("bridges"), fingerprintHex)
    }

    fun learnedBridgeIdentity(host: String, port: Int): String? =
        bridgeIdentityByAddr["${host.lowercase()}:$port"]

    /** C Tor `entries_known_but_down`. */
    fun entriesKnownButDown(config: TorConfig): Boolean {
        if (!useEntryGuards(config)) return false
        val gs = getGuardSelectionInfo()
        if (gs.sampled.isEmpty()) return false
        return gs.sampled.all { it.reachable == GuardReachable.NO }
    }

    /** C Tor `entries_retry_all`. */
    fun entriesRetryAll(config: TorConfig) {
        if (!useEntryGuards(config)) return
        val now = System.currentTimeMillis() / 1000
        for (g in getGuardSelectionInfo().sampled) {
            if (g.reachable != GuardReachable.YES) {
                g.reachable = GuardReachable.MAYBE
                g.isPending = false
                g.lastAttemptEpochSec = now - 10_000 // force considerRetry eligible
            }
        }
        for (g in defaultFsm.all()) {
            if (g.reachable != GuardReachable.YES) {
                g.reachable = GuardReachable.MAYBE
                g.isPending = false
                g.lastAttemptEpochSec = now - 10_000
            }
        }
    }

    /** Reset selections (tests). */
    fun entryGuardsFreeAll() {
        selections.clear()
        bridgeIdentityByAddr.clear()
    }
}

/** C Tor `guard_selection_t`. */
class GuardSelection(
    val name: String,
    val fsm: EntryGuardFsm = EntryGuardFsm(),
) {
    val sampled: CopyOnWriteArrayList<EntryGuardRuntime> = CopyOnWriteArrayList()
}

/** C Tor `entry_guard_restriction_t`. */
data class EntryGuardRestriction(
    val excludedFingerprints: Set<String> = emptySet(),
)

/** C Tor circuit guard wait states (subset). */
enum class CircGuardStateKind {
    WAITING_FOR_BETTER,
    COMPLETE,
    DEAD,
}

/** C Tor `guard_usable_t`. */
enum class GuardUsable {
    NOW,
    LATER,
    NEVER,
}

/** C Tor `circuit_guard_state_t`. */
data class CircuitGuardState(
    val id: Long,
    val guardFingerprint: String,
    var state: CircGuardStateKind,
    val createdEpochSec: Long,
    val restrictions: EntryGuardRestriction? = null,
)

/** C Tor `guard_pathbias_t` fields used by entrynodes. */
data class GuardPathbiasState(
    var circAttemptCount: Double = 0.0,
    var circSuccessCount: Double = 0.0,
    var successfulCloseCount: Double = 0.0,
    var collapsedCount: Double = 0.0,
    var unusableCount: Double = 0.0,
    var timeoutCount: Double = 0.0,
)
