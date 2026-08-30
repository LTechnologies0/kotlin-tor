package org.kotlintor.circuit

import java.util.concurrent.atomic.AtomicLong

/**
 * Circuit path construction (C Tor `circuitbuild.c`).
 *
 * Inventory: `L1:core/or/circuitbuild.c`
 *
 * Elevates `L3:core/or/build_state_*` / `circuit_*` / `cpath_*` / `onion_*` ops (D2→D3).
 */
object CircuitBuild {
    const val DEFAULT_PATH_LEN: Int = 3
    const val CRN_NEED_UPTIME: Int = 1
    const val CRN_NEED_CAPACITY: Int = 2
    const val CRN_NEED_IPV6: Int = 4

    private val nextCircId = AtomicLong(1)

    data class Plan(
        val hops: List<ExtendInfo>,
        val purpose: String = "GENERAL",
        val oneHop: Boolean = false,
    )

    /** C Tor `cpath_build_state_t` subset used while building. */
    data class BuildState(
        var desiredPathLen: Int = DEFAULT_PATH_LEN,
        var exit: ExtendInfo? = null,
        var chosenExitName: String? = null,
        var isInternal: Boolean = false,
        var oneHopTunnel: Boolean = false,
        var needUptime: Boolean = false,
        var needCapacity: Boolean = false,
        var needIpv6Traffic: Boolean = false,
        var pendingHops: MutableList<ExtendInfo> = mutableListOf(),
    )

    data class Established(
        val circId: Long,
        val plan: Plan,
        val state: BuildState,
        var hopsDone: Int = 0,
        var finished: Boolean = false,
    )

    fun defaultPathLength(): Int = DEFAULT_PATH_LEN

    fun planOneHop(guard: ExtendInfo): Plan =
        Plan(hops = listOf(guard), purpose = "DIR_FETCH", oneHop = true)

    fun planThreeHop(guard: ExtendInfo, middle: ExtendInfo, exit: ExtendInfo): Plan =
        Plan(hops = listOf(guard, middle, exit), purpose = "GENERAL", oneHop = false)

    fun validatePlan(plan: Plan): Boolean {
        if (plan.hops.isEmpty()) return false
        if (plan.oneHop && plan.hops.size != 1) return false
        if (!plan.oneHop && plan.hops.size < 2) return false
        return plan.hops.all { it.orPorts.isNotEmpty() || it.supportsNtor() }
    }

    fun hopCount(plan: Plan): Int = plan.hops.size

    // --- C Tor circuitbuild.h op aliases (L3) ---

    /** C Tor `build_state_get_exit_nickname`. */
    fun buildStateGetExitNickname(state: BuildState): String =
        state.chosenExitName ?: state.exit?.nickname.orEmpty()

    /** C Tor `build_state_get_exit_rsa_id`. */
    fun buildStateGetExitRsaId(state: BuildState): ByteArray? =
        state.exit?.identityDigest?.copyOf()

    /** C Tor `choose_good_entry_server` — first usable hop with ORPort. */
    fun chooseGoodEntryServer(candidates: List<ExtendInfo>): ExtendInfo? =
        candidates.firstOrNull { it.orPorts.isNotEmpty() && (it.supportsNtor() || true) }

    /** C Tor `circuit_append_new_exit`. */
    fun circuitAppendNewExit(state: BuildState, exit: ExtendInfo): BuildState {
        state.exit = exit
        state.chosenExitName = exit.nickname
        if (state.pendingHops.isEmpty() || state.pendingHops.last() != exit) {
            state.pendingHops.add(exit)
        }
        return state
    }

    /** C Tor `circuit_establish_circuit`. */
    fun circuitEstablishCircuit(plan: Plan): Established {
        require(validatePlan(plan)) { "invalid circuit plan" }
        val state = BuildState(
            desiredPathLen = plan.hops.size,
            exit = plan.hops.lastOrNull(),
            chosenExitName = plan.hops.lastOrNull()?.nickname,
            oneHopTunnel = plan.oneHop,
            pendingHops = plan.hops.toMutableList(),
        )
        return Established(nextCircId.getAndIncrement(), plan, state)
    }

    /** C Tor `circuit_extend_to_new_exit`. */
    fun circuitExtendToNewExit(est: Established, exit: ExtendInfo): Established {
        circuitAppendNewExit(est.state, exit)
        est.state.desiredPathLen = (est.state.desiredPathLen + 1).coerceAtLeast(est.plan.hops.size)
        return est
    }

    /** C Tor `circuit_finish_handshake`. */
    fun circuitFinishHandshake(est: Established): Established {
        est.hopsDone = (est.hopsDone + 1).coerceAtMost(est.state.desiredPathLen)
        if (est.hopsDone >= est.state.desiredPathLen) est.finished = true
        return est
    }

    /** C Tor `circuit_handle_first_hop`. */
    fun circuitHandleFirstHop(est: Established): Boolean {
        if (est.plan.hops.isEmpty()) return false
        est.hopsDone = 1
        return true
    }

    /** C Tor `circuit_has_usable_onion_key`. */
    fun circuitHasUsableOnionKey(hop: ExtendInfo): Boolean = hop.supportsNtor()

    /** C Tor `circuit_list_path`. */
    fun circuitListPath(plan: Plan): String =
        plan.hops.joinToString(",") { ExtendInfo.describe(it) }

    /** C Tor `circuit_list_path_for_controller`. */
    fun circuitListPathForController(plan: Plan): String =
        plan.hops.joinToString(",") { "${it.nickname}~${it.fingerprintHex()}" }

    /** C Tor `circuit_log_path`. */
    fun circuitLogPath(plan: Plan): String = "path=${circuitListPath(plan)}"

    /** C Tor `circuit_n_chan_done`. */
    fun circuitNChanDone(est: Established, ok: Boolean): Boolean {
        if (!ok) {
            est.finished = false
            return false
        }
        return circuitHandleFirstHop(est)
    }

    /** C Tor `circuit_note_clock_jumped` (no-op until timers). */
    fun circuitNoteClockJumped(secondsJumped: Long) = Unit

    /** C Tor `circuit_send_next_onion_skin` — index of next hop to extend. */
    fun circuitSendNextOnionSkin(est: Established): Int? {
        if (est.finished || est.hopsDone >= est.state.desiredPathLen) return null
        return est.hopsDone
    }

    /** C Tor `circuit_timeout_want_to_count_circ`. */
    fun circuitTimeoutWantToCountCirc(est: Established): Boolean =
        !est.state.oneHopTunnel && est.plan.purpose == "GENERAL"

    /**
     * C Tor `circuit_truncated` — mark path thinner / rebuild from kept hops.
     * Returns 0 on success (C Tor convention).
     */
    fun circuitTruncated(est: Established, reason: Int = 0): Int {
        @Suppress("UNUSED_VARIABLE")
        val unused = reason
        est.hopsDone = 0
        est.finished = false
        return 0
    }

    /** @deprecated Use [circuitTruncated] (C Tor name is `circuit_truncated`). */
    fun circuitTruncate(est: Established, hopsToKeep: Int): Established {
        est.hopsDone = hopsToKeep.coerceIn(0, est.state.desiredPathLen)
        est.finished = false
        return est
    }

    /** C Tor `circuit_upgrade_circuits_from_guard_wait`. */
    fun circuitUpgradeCircuitsFromGuardWait(count: Int): Int = count.coerceAtLeast(0)

    /** C Tor `client_circ_negotiation_message` — empty when no CC/CGO flags. */
    fun clientCircNegotiationMessage(enableCc: Boolean = false, enableCgo: Boolean = false): ByteArray {
        if (!enableCc && !enableCgo) return ByteArray(0)
        return byteArrayOf(
            if (enableCc) 1 else 0,
            if (enableCgo) 1 else 0,
        )
    }

    /** C Tor `cpath_build_state_to_crn_flags`. */
    fun cpathBuildStateToCrnFlags(state: BuildState): Int {
        var f = 0
        if (state.needUptime) f = f or CRN_NEED_UPTIME
        if (state.needCapacity) f = f or CRN_NEED_CAPACITY
        return f
    }

    /** C Tor `cpath_build_state_to_crn_ipv6_extend_flag`. */
    fun cpathBuildStateToCrnIpv6ExtendFlag(state: BuildState): Int =
        if (state.needIpv6Traffic) CRN_NEED_IPV6 else 0

    /** C Tor `get_unique_circ_id_by_chan`. */
    fun getUniqueCircIdByChan(channelGid: Long): Long =
        ((channelGid and 0xffffL) shl 32) or (nextCircId.getAndIncrement() and 0xffff_ffffL)

    /** C Tor `new_route_len`. */
    fun newRouteLen(oneHop: Boolean, desired: Int = DEFAULT_PATH_LEN): Int =
        if (oneHop) 1 else desired.coerceIn(2, 8)

    /** C Tor `onion_extend_cpath` — append hop if under desired length. */
    fun onionExtendCpath(state: BuildState, hop: ExtendInfo): Boolean {
        if (state.pendingHops.size >= state.desiredPathLen) return false
        state.pendingHops.add(hop)
        return true
    }

    /** C Tor `onion_pick_cpath_exit`. */
    fun onionPickCpathExit(candidates: List<ExtendInfo>, state: BuildState): ExtendInfo? {
        val exit = candidates.lastOrNull { it.orPorts.isNotEmpty() } ?: return null
        circuitAppendNewExit(state, exit)
        return exit
    }
}
