package org.kotlintor.circuit

/**
 * Conflux helpers (C Tor `conflux_util.c`).
 *
 * Inventory: `L1:core/or/conflux_util.c`
 */
object ConfluxUtil {
    data class LegState(
        val circId: Long,
        var rttMs: Long = Long.MAX_VALUE,
        var canSend: Boolean = true,
        var markedForClose: Boolean = false,
    )

    data class SetState(
        val nonce: ByteArray,
        val legs: MutableList<LegState> = mutableListOf(),
        var currLegCircId: Long? = null,
        var inFullTeardown: Boolean = false,
        var linked: Boolean = false,
    )

    /** C Tor `conflux_can_send` — true when a usable current/next leg exists. */
    fun canSend(set: SetState): Boolean {
        if (set.inFullTeardown) return false
        val curr = set.currLegCircId
        if (curr != null) {
            val leg = set.legs.firstOrNull { it.circId == curr }
            if (leg != null && leg.canSend && !leg.markedForClose) return true
        }
        return decideNextCirc(set) != null
    }

    /** Pick lowest-RTT sendable leg (LOWRTT-ish). */
    fun decideNextCirc(set: SetState): Long? =
        set.legs
            .filter { it.canSend && !it.markedForClose }
            .minByOrNull { it.rttMs }
            ?.circId

    /** C Tor `conflux_validate_legs` — leg count within params. */
    fun validateLegs(set: SetState, maxLegs: Int = ConfluxParams.getMaxLegsSet()): Boolean {
        if (set.nonce.size != 32) return false
        val n = set.legs.size
        return n in 1..maxLegs
    }

    fun getNonce(set: SetState): ByteArray = set.nonce.copyOf()

    fun getCircRtt(set: SetState, circId: Long): Long =
        set.legs.firstOrNull { it.circId == circId }?.rttMs ?: Long.MAX_VALUE

    fun noteRtt(set: SetState, circId: Long, rttMs: Long) {
        val leg = set.legs.firstOrNull { it.circId == circId } ?: return
        leg.rttMs = rttMs.coerceAtLeast(1)
        if (set.currLegCircId == null) set.currLegCircId = circId
    }

    fun addLeg(set: SetState, circId: Long): LegState {
        val existing = set.legs.firstOrNull { it.circId == circId }
        if (existing != null) return existing
        val leg = LegState(circId)
        set.legs += leg
        if (set.currLegCircId == null) set.currLegCircId = circId
        return leg
    }

    /** C Tor `conflux_can_send`. */
    fun confluxCanSend(set: SetState): Boolean = canSend(set)

    /** C Tor `conflux_get_nonce`. */
    fun confluxGetNonce(set: SetState): ByteArray = getNonce(set)

    /** C Tor `conflux_get_circ_rtt`. */
    fun confluxGetCircRtt(set: SetState, circId: Long): Long = getCircRtt(set, circId)

    /** C Tor `circuit_get_package_window`. */
    fun circuitGetPackageWindow(packageWindow: Int, cpathWindow: Int? = null): Int =
        cpathWindow ?: packageWindow

    /** C Tor `conflux_get_destination_hop` — last hop index. */
    fun confluxGetDestinationHop(hopCount: Int): Int = (hopCount - 1).coerceAtLeast(0)

    /** C Tor `conflux_validate_legs`. */
    fun confluxValidateLegs(set: SetState): Boolean = validateLegs(set)

    /** C Tor `conflux_validate_source_hop`. */
    fun confluxValidateSourceHop(inCircId: Long, expectedCircId: Long?): Boolean =
        expectedCircId == null || inCircId == expectedCircId

    /** C Tor `conflux_validate_stream_lists`. */
    fun confluxValidateStreamLists(set: SetState): Boolean =
        set.legs.none { it.markedForClose && it.canSend }

    /** C Tor `conflux_sync_circ_fields`. */
    fun confluxSyncCircFields(set: SetState, refCircId: Long) {
        if (set.legs.any { it.circId == refCircId }) {
            set.currLegCircId = refCircId
        }
    }

    /** C Tor `conflux_update_p_streams` / half / n / resolving — no-op stubs with C names. */
    fun confluxUpdatePStreams(streamCount: Int): Int = streamCount

    fun confluxUpdateHalfStreams(streamCount: Int): Int = streamCount

    fun confluxUpdateNStreams(streamCount: Int): Int = streamCount

    fun confluxUpdateResolvingStreams(streamCount: Int): Int = streamCount

    /** C Tor `edge_uses_cpath`. */
    fun edgeUsesCpath(hasCpath: Boolean): Boolean = hasCpath

    /** C Tor `edge_get_max_rtt`. */
    fun edgeGetMaxRtt(set: SetState): Long =
        set.legs.maxOfOrNull { it.rttMs } ?: Long.MAX_VALUE

    /** C Tor `relay_crypt_from_last_hop`. */
    fun relayCryptFromLastHop(hopIndex: Int, hopCount: Int): Boolean =
        hopCount > 0 && hopIndex == hopCount - 1
}
