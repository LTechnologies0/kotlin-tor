package org.kotlintor.circuit

import org.kotlintor.cell.CircuitPurpose
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Circuit use / purpose helpers (C Tor `circuituse.c`).
 *
 * Inventory: `L1:core/or/circuituse.c`
 */
object CircuitUse {
    enum class Purpose {
        GENERAL,
        HS_CLIENT_INTRO,
        HS_CLIENT_REND,
        HS_SERVICE_INTRO,
        HS_SERVICE_REND,
        TESTING,
        CONTROLLER,
        MEASURE_TIMEOUT,
        S_VANGUARDS,
        PATH_BIAS_TESTING,
        HS_VANGUARDS,
        CIRCUIT_PADDING,
        CONFLUX_UNLINKED,
        CONFLUX_LINKED,
    }

    data class UseState(
        val purpose: Purpose = Purpose.GENERAL,
        val dirty: Boolean = false,
        val isolationToken: String? = null,
        val lastHopConnectedMs: Long = 0,
        val usable: Boolean = true,
        val circId: Long = 0,
        val opened: Boolean = false,
        val buildFailed: Boolean = false,
        val portsHandled: Set<Int> = emptySet(),
        val validDataBytes: Long = 0,
        val hsV3: Boolean = false,
    )

    private val failureCount = AtomicInteger(0)
    private val byId = ConcurrentHashMap<Long, UseState>()

    fun purposeName(p: Purpose): String = p.name.lowercase()

    fun isHsPurpose(p: Purpose): Boolean =
        p == Purpose.HS_CLIENT_INTRO || p == Purpose.HS_CLIENT_REND ||
            p == Purpose.HS_SERVICE_INTRO || p == Purpose.HS_SERVICE_REND ||
            p == Purpose.HS_VANGUARDS

    fun isConfluxPurpose(p: Purpose): Boolean =
        p == Purpose.CONFLUX_UNLINKED || p == Purpose.CONFLUX_LINKED

    /** C Tor-ish: dirty circuits should not take new streams past dirty timeout. */
    fun canAttachStream(state: UseState, nowMs: Long, dirtyTimeoutMs: Long): Boolean {
        if (!state.usable) return false
        if (!state.dirty) return true
        if (dirtyTimeoutMs <= 0) return true
        if (state.lastHopConnectedMs <= 0) return false
        return nowMs - state.lastHopConnectedMs < dirtyTimeoutMs
    }

    fun markDirty(state: UseState, nowMs: Long): UseState =
        state.copy(dirty = true, lastHopConnectedMs = if (state.lastHopConnectedMs == 0L) nowMs else state.lastHopConnectedMs)

    fun put(state: UseState) {
        if (state.circId != 0L) byId[state.circId] = state
    }

    fun get(circId: Long): UseState? = byId[circId]

    fun clear() {
        byId.clear()
        failureCount.set(0)
    }

    // --- C Tor circuituse.h op aliases (L3) ---

    /** C Tor `circuit_build_failed`. */
    fun circuitBuildFailed(circId: Long): UseState? {
        failureCount.incrementAndGet()
        val s = byId[circId] ?: return null
        val n = s.copy(buildFailed = true, usable = false)
        byId[circId] = n
        return n
    }

    /** C Tor `circuit_build_needed_circs` — desired idle GENERAL count. */
    fun circuitBuildNeededCircs(have: Int, want: Int = 3): Int = (want - have).coerceAtLeast(0)

    /** C Tor `circuit_change_purpose`. */
    fun circuitChangePurpose(state: UseState, purpose: Purpose): UseState {
        val n = state.copy(purpose = purpose)
        if (n.circId != 0L) byId[n.circId] = n
        return n
    }

    /** C Tor `circuit_conforms_to_options` — isolation / purpose gate. */
    fun circuitConformsToOptions(state: UseState, requireIsolation: String? = null): Boolean {
        if (!state.usable || state.buildFailed) return false
        if (requireIsolation != null && state.isolationToken != requireIsolation) return false
        return true
    }

    /** C Tor `circuit_detach_stream`. */
    fun circuitDetachStream(state: UseState): UseState = state.copy(usable = state.usable)

    /** C Tor `circuit_enough_testing_circs`. */
    fun circuitEnoughTestingCircs(testingOpen: Int, need: Int = 1): Boolean = testingOpen >= need

    /** C Tor `circuit_expire_building`. */
    fun circuitExpireBuilding(nowMs: Long, buildTimeoutMs: Long): List<Long> =
        byId.values.filter {
            !it.opened && it.lastHopConnectedMs > 0 && nowMs - it.lastHopConnectedMs > buildTimeoutMs
        }.map { it.circId }

    /** C Tor `circuit_expire_old_circs_as_needed`. */
    fun circuitExpireOldCircsAsNeeded(nowMs: Long, maxIdleMs: Long): List<Long> =
        byId.values.filter {
            it.dirty && it.opened && nowMs - it.lastHopConnectedMs > maxIdleMs
        }.map { it.circId }

    /** C Tor `circuit_expire_old_circuits_serverside`. */
    fun circuitExpireOldCircuitsServerside(nowMs: Long, maxAgeMs: Long): List<Long> =
        circuitExpireOldCircsAsNeeded(nowMs, maxAgeMs)

    /** C Tor `circuit_expire_waiting_for_better_guard`. */
    fun circuitExpireWaitingForBetterGuard(): List<Long> =
        byId.values.filter { !it.opened && it.purpose == Purpose.GENERAL }.map { it.circId }

    /** C Tor `circuit_get_best`. */
    fun circuitGetBest(purpose: Purpose = Purpose.GENERAL): UseState? =
        byId.values.filter { it.purpose == purpose && circuitIsAcceptable(it) }
            .maxByOrNull { it.validDataBytes }

    /** C Tor `circuit_has_opened`. */
    fun circuitHasOpened(state: UseState): UseState {
        val n = state.copy(opened = true, usable = true)
        if (n.circId != 0L) byId[n.circId] = n
        return n
    }

    /** C Tor `circuit_is_acceptable`. */
    fun circuitIsAcceptable(state: UseState): Boolean =
        state.usable && state.opened && !state.buildFailed

    /** C Tor `circuit_is_available_for_use`. */
    fun circuitIsAvailableForUse(state: UseState): Boolean =
        circuitIsAcceptable(state) && !state.dirty

    /** C Tor `circuit_is_hs_v3`. */
    fun circuitIsHsV3(state: UseState): Boolean = state.hsV3 || isHsPurpose(state.purpose)

    /** C Tor `circuit_launch`. */
    fun circuitLaunch(purpose: Purpose = Purpose.GENERAL, circId: Long = System.nanoTime()): UseState {
        val s = UseState(purpose = purpose, circId = circId, lastHopConnectedMs = System.currentTimeMillis())
        byId[circId] = s
        return s
    }

    /** C Tor `circuit_launch_by_extend_info`. */
    fun circuitLaunchByExtendInfo(
        exit: ExtendInfo,
        purpose: Purpose = Purpose.GENERAL,
    ): UseState = circuitLaunch(purpose).copy(isolationToken = exit.nickname).also { put(it) }

    /** C Tor `circuit_log_ancient_one_hop_circuits`. */
    fun circuitLogAncientOneHopCircuits(count: Int): String = "ancient_one_hop=$count"

    /** C Tor `circuit_purpose_is_hidden_service`. */
    fun circuitPurposeIsHiddenService(p: Purpose): Boolean = isHsPurpose(p)

    fun circuitPurposeIsHiddenService(p: CircuitPurpose): Boolean =
        CircuitList.purposeToHsStateString(p) != null ||
            p.name.contains("HS_")

    /** C Tor `circuit_purpose_is_hs_client`. */
    fun circuitPurposeIsHsClient(p: Purpose): Boolean =
        p == Purpose.HS_CLIENT_INTRO || p == Purpose.HS_CLIENT_REND

    /** C Tor `circuit_purpose_is_hs_service`. */
    fun circuitPurposeIsHsService(p: Purpose): Boolean =
        p == Purpose.HS_SERVICE_INTRO || p == Purpose.HS_SERVICE_REND

    /** C Tor `circuit_purpose_is_hs_vanguards`. */
    fun circuitPurposeIsHsVanguards(p: Purpose): Boolean =
        p == Purpose.HS_VANGUARDS || p == Purpose.S_VANGUARDS

    /** C Tor `circuit_read_valid_data`. */
    fun circuitReadValidData(state: UseState, nbytes: Long): UseState {
        val n = state.copy(validDataBytes = state.validDataBytes + nbytes.coerceAtLeast(0))
        if (n.circId != 0L) byId[n.circId] = n
        return n
    }

    /** C Tor `circuit_remove_handled_ports`. */
    fun circuitRemoveHandledPorts(state: UseState, ports: Set<Int>): UseState {
        val n = state.copy(portsHandled = state.portsHandled - ports)
        if (n.circId != 0L) byId[n.circId] = n
        return n
    }

    /** C Tor `circuit_reset_failure_count`. */
    fun circuitResetFailureCount() {
        failureCount.set(0)
    }

    fun failureCount(): Int = failureCount.get()
}
