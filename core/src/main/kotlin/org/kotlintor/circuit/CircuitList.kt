package org.kotlintor.circuit

import org.kotlintor.cell.CircuitPurpose
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Global circuit table (C Tor `circuitlist.c`).
 *
 * Inventory: `L1:core/or/circuitlist.c`
 *
 * Tracks [CircuitMeta] for origin and OR circuits; purpose/state string maps
 * mirror `circuit_purpose_to_*` / `circuit_state_to_string`; mark-for-close
 * mirrors `circuit_mark_for_close` / `circuit_close_all_marked`.
 */
object CircuitList {
    private val byId = ConcurrentHashMap<Long, CircuitMeta>()
    private val anyOpenedCached = AtomicBoolean(false)

    fun put(meta: CircuitMeta) {
        byId[meta.kind.circId] = meta
    }

    fun get(circId: Long): CircuitMeta? = byId[circId]

    fun remove(circId: Long): CircuitMeta? = byId.remove(circId)

    fun all(): Collection<CircuitMeta> = byId.values

    /** C Tor `circuit_get_global_list` (all circuits). */
    fun globalList(): List<CircuitMeta> = byId.values.toList()

    /** C Tor `circuit_get_global_origin_circuit_list`. */
    fun globalOriginList(): List<CircuitMeta> = origins()

    fun origins(): List<CircuitMeta> = byId.values.filter { it.isOrigin }

    fun ors(): List<CircuitMeta> = byId.values.filter { it.isOr }

    fun count(): Int = byId.size

    fun clear() {
        byId.clear()
        anyOpenedCached.set(false)
        unusableCircIds.clear()
        destroyPending.clear()
    }

    fun byPurpose(purpose: CircuitPurpose): List<CircuitMeta> =
        byId.values.filter { it.purpose == purpose }

    fun markDirty(circId: Long) {
        byId[circId]?.dirty = true
    }

    fun dirtyCircuits(): List<CircuitMeta> = byId.values.filter { it.dirty }

    fun countOrigins(): Int = origins().size

    fun countOrs(): Int = ors().size

    fun registerOrigin(
        circId: Long,
        purpose: CircuitPurpose = CircuitPurpose.GENERAL,
        pathLength: Int = 3,
    ): CircuitMeta {
        val meta = CircuitMeta(CircuitKind.Origin(circId, purpose, pathLength))
        put(meta)
        return meta
    }

    fun registerOr(
        circId: Long,
        isExit: Boolean = false,
        isDir: Boolean = false,
        purpose: CircuitPurpose = CircuitPurpose.OR,
    ): CircuitMeta {
        val meta = CircuitMeta(
            CircuitKind.Or(circId, purpose = purpose, isExit = isExit, isDir = isDir, cryptoEstablished = true),
        )
        put(meta)
        return meta
    }

    /** C Tor mark-for-close path (deferred free). */
    fun markForClose(circId: Long): Boolean {
        val m = byId[circId] ?: return false
        m.markedForClose = true
        return true
    }

    /** C Tor `circuit_count_pending_close`. */
    fun countPendingClose(): Int = byId.values.count { it.markedForClose }

    /** C Tor `circuit_close_all_marked` — removes marked entries; returns count closed. */
    fun closeAllMarked(): Int {
        val ids = byId.values.filter { it.markedForClose }.map { it.kind.circId }
        for (id in ids) byId.remove(id)
        return ids.size
    }

    /** C Tor `circuit_any_opened_circuits`. */
    fun anyOpenedCircuits(): Boolean =
        byId.values.any { it.isOrigin && (it.kind as? CircuitKind.Origin)?.hasOpened == true }

    /** C Tor `circuit_cache_opened_circuit_state`. */
    fun cacheOpenedCircuitState(opened: Boolean) {
        anyOpenedCached.set(opened)
    }

    /** C Tor `circuit_any_opened_circuits_cached`. */
    fun anyOpenedCircuitsCached(): Boolean = anyOpenedCached.get()

    /** C Tor `circuit_state_to_string`. */
    fun circuitStateToString(state: CircuitState): String = stateToString(state)

    fun stateToString(state: CircuitState): String = when (state) {
        CircuitState.BUILDING -> "doing handshakes"
        CircuitState.ONIONSKIN_PENDING -> "processing the onion"
        CircuitState.CHAN_WAIT -> "connecting to server"
        CircuitState.GUARD_WAIT -> "waiting to see how other guards perform"
        CircuitState.OPEN -> "open"
    }

    /** C Tor `circuit_purpose_to_controller_string`. */
    fun circuitPurposeToControllerString(purpose: CircuitPurpose): String =
        purposeToControllerString(purpose)

    fun purposeToControllerString(purpose: CircuitPurpose): String = when (purpose) {
        CircuitPurpose.OR,
        CircuitPurpose.INTRO_POINT,
        CircuitPurpose.REND_POINT_WAITING,
        CircuitPurpose.REND_ESTABLISHED,
        -> "SERVER"
        CircuitPurpose.GENERAL, CircuitPurpose.DIR_FETCH, CircuitPurpose.DIR_UPLOAD -> "GENERAL"
        CircuitPurpose.HS_CLIENT_HSDIR -> "HS_CLIENT_HSDIR"
        CircuitPurpose.HS_CLIENT_INTRODUCING,
        CircuitPurpose.HS_CLIENT_INTRO_ACK_WAIT,
        CircuitPurpose.HS_CLIENT_INTRO_ACKED,
        CircuitPurpose.HS_CLIENT_INTRO,
        -> "HS_CLIENT_INTRO"
        CircuitPurpose.HS_CLIENT_ESTABLISH_REND,
        CircuitPurpose.HS_CLIENT_REND_READY,
        CircuitPurpose.HS_CLIENT_REND_READY_INTRO_ACKED,
        CircuitPurpose.HS_CLIENT_REND_JOINED,
        CircuitPurpose.HS_CLIENT_REND,
        -> "HS_CLIENT_REND"
        CircuitPurpose.HS_SERVICE_HSDIR -> "HS_SERVICE_HSDIR"
        CircuitPurpose.HS_SERVICE_ESTABLISH_INTRO,
        CircuitPurpose.HS_SERVICE_INTRO,
        -> "HS_SERVICE_INTRO"
        CircuitPurpose.HS_SERVICE_CONNECT_REND,
        CircuitPurpose.HS_SERVICE_REND_JOINED,
        CircuitPurpose.HS_SERVICE_REND,
        -> "HS_SERVICE_REND"
        CircuitPurpose.TESTING -> "TESTING"
        CircuitPurpose.MEASURE_TIMEOUT -> "MEASURE_TIMEOUT"
        CircuitPurpose.CONTROLLER -> "CONTROLLER"
        CircuitPurpose.PATH_BIAS_TESTING -> "PATH_BIAS_TESTING"
        CircuitPurpose.HS_VANGUARDS -> "HS_VANGUARDS"
        CircuitPurpose.CIRCUIT_PADDING -> "CIRCUIT_PADDING"
        CircuitPurpose.CONFLUX_UNLINKED -> "CONFLUX_UNLINKED"
        CircuitPurpose.CONFLUX_LINKED -> "CONFLUX_LINKED"
    }

    /** C Tor `circuit_purpose_to_controller_hs_state_string` (null if not HS). */
    fun circuitPurposeToControllerHsStateString(purpose: CircuitPurpose): String? =
        purposeToHsStateString(purpose)

    fun purposeToHsStateString(purpose: CircuitPurpose): String? = when (purpose) {
        CircuitPurpose.INTRO_POINT -> "OR_HSSI_ESTABLISHED"
        CircuitPurpose.REND_POINT_WAITING -> "OR_HSCR_ESTABLISHED"
        CircuitPurpose.REND_ESTABLISHED -> "OR_HS_R_JOINED"
        CircuitPurpose.HS_CLIENT_HSDIR,
        CircuitPurpose.HS_CLIENT_INTRODUCING,
        CircuitPurpose.HS_CLIENT_INTRO,
        -> "HSCI_CONNECTING"
        CircuitPurpose.HS_CLIENT_INTRO_ACK_WAIT -> "HSCI_INTRO_SENT"
        CircuitPurpose.HS_CLIENT_INTRO_ACKED -> "HSCI_DONE"
        CircuitPurpose.HS_CLIENT_ESTABLISH_REND -> "HSCR_CONNECTING"
        CircuitPurpose.HS_CLIENT_REND_READY -> "HSCR_ESTABLISHED_IDLE"
        CircuitPurpose.HS_CLIENT_REND_READY_INTRO_ACKED -> "HSCR_ESTABLISHED_WAITING"
        CircuitPurpose.HS_CLIENT_REND_JOINED, CircuitPurpose.HS_CLIENT_REND -> "HSCR_JOINED"
        CircuitPurpose.HS_SERVICE_HSDIR,
        CircuitPurpose.HS_SERVICE_ESTABLISH_INTRO,
        -> "HSSI_CONNECTING"
        CircuitPurpose.HS_SERVICE_INTRO -> "HSSI_ESTABLISHED"
        CircuitPurpose.HS_SERVICE_CONNECT_REND -> "HSSR_CONNECTING"
        CircuitPurpose.HS_SERVICE_REND_JOINED, CircuitPurpose.HS_SERVICE_REND -> "HSSR_JOINED"
        else -> null
    }

    /** C Tor `circuit_purpose_to_string`. */
    fun circuitPurposeToString(purpose: CircuitPurpose): String = purposeToString(purpose)

    fun purposeToString(purpose: CircuitPurpose): String = when (purpose) {
        CircuitPurpose.OR -> "Circuit at relay"
        CircuitPurpose.INTRO_POINT -> "Acting as intro point"
        CircuitPurpose.REND_POINT_WAITING -> "Acting as rendezvous (pending)"
        CircuitPurpose.REND_ESTABLISHED -> "Acting as rendezvous (established)"
        CircuitPurpose.GENERAL -> "General-purpose client"
        CircuitPurpose.DIR_FETCH -> "Directory fetch"
        CircuitPurpose.DIR_UPLOAD -> "Directory upload"
        CircuitPurpose.HS_CLIENT_INTRODUCING, CircuitPurpose.HS_CLIENT_INTRO ->
            "Hidden service client: Connecting to intro point"
        CircuitPurpose.HS_CLIENT_INTRO_ACK_WAIT ->
            "Hidden service client: Waiting for ack from intro point"
        CircuitPurpose.HS_CLIENT_INTRO_ACKED ->
            "Hidden service client: Received ack from intro point"
        CircuitPurpose.HS_CLIENT_ESTABLISH_REND ->
            "Hidden service client: Establishing rendezvous point"
        CircuitPurpose.HS_CLIENT_REND_READY ->
            "Hidden service client: Pending rendezvous point"
        CircuitPurpose.HS_CLIENT_REND_READY_INTRO_ACKED ->
            "Hidden service client: Pending rendezvous point (ack received)"
        CircuitPurpose.HS_CLIENT_REND_JOINED, CircuitPurpose.HS_CLIENT_REND ->
            "Hidden service client: Active rendezvous point"
        CircuitPurpose.HS_CLIENT_HSDIR -> "Hidden service client: Fetching HS descriptor"
        CircuitPurpose.MEASURE_TIMEOUT -> "Measuring circuit timeout"
        CircuitPurpose.HS_SERVICE_ESTABLISH_INTRO ->
            "Hidden service: Establishing introduction point"
        CircuitPurpose.HS_SERVICE_INTRO -> "Hidden service: Introduction point"
        CircuitPurpose.HS_SERVICE_CONNECT_REND ->
            "Hidden service: Connecting to rendezvous point"
        CircuitPurpose.HS_SERVICE_REND_JOINED, CircuitPurpose.HS_SERVICE_REND ->
            "Hidden service: Active rendezvous point"
        CircuitPurpose.HS_SERVICE_HSDIR -> "Hidden service: Uploading HS descriptor"
        CircuitPurpose.TESTING -> "Testing circuit"
        CircuitPurpose.CONTROLLER -> "Circuit made by controller"
        CircuitPurpose.PATH_BIAS_TESTING -> "Path-bias testing circuit"
        CircuitPurpose.HS_VANGUARDS -> "Hidden service: Pre-built vanguard circuit"
        CircuitPurpose.CIRCUIT_PADDING -> "Circuit kept open for padding"
        CircuitPurpose.CONFLUX_UNLINKED -> "Unlinked conflux circuit"
        CircuitPurpose.CONFLUX_LINKED -> "Linked conflux circuit"
    }

    // --- additional circuitlist.h L3 aliases ---

    private val unusableCircIds = ConcurrentHashMap.newKeySet<Long>()
    private val destroyPending = ConcurrentHashMap.newKeySet<Long>()

    /** C Tor `channel_mark_circid_unusable`. */
    fun channelMarkCircidUnusable(circId: Long) {
        unusableCircIds.add(circId)
    }

    /** C Tor `channel_mark_circid_usable`. */
    fun channelMarkCircidUsable(circId: Long) {
        unusableCircIds.remove(circId)
    }

    fun isCircidUnusable(circId: Long): Boolean = unusableCircIds.contains(circId)

    /** C Tor `channel_note_destroy_pending`. */
    fun channelNoteDestroyPending(circId: Long) {
        destroyPending.add(circId)
    }

    /** C Tor `circuit_clear_cpath`. */
    fun circuitClearCpath(meta: CircuitMeta) {
        meta.cpath.clear()
        meta.pathLength = 0
    }

    /** C Tor `circuit_clear_testing_cell_stats`. */
    fun circuitClearTestingCellStats(meta: CircuitMeta) {
        meta.testingCellStats = 0
    }

    /** C Tor `circuit_count_pending_on_channel`. */
    fun circuitCountPendingOnChannel(channelGid: Long): Int =
        byId.values.count { it.channelGid == channelGid && it.state == CircuitState.CHAN_WAIT }

    /** C Tor `circuit_dump_by_conn`. */
    fun circuitDumpByConn(channelGid: Long): String =
        byId.values.filter { it.channelGid == channelGid }
            .joinToString("\n") { "circ=${it.kind.circId} state=${it.state} purpose=${it.purpose}" }

    /** C Tor `circuit_event_status`. */
    fun circuitEventStatus(meta: CircuitMeta): String =
        "CIRC ${meta.kind.circId} ${circuitStateToString(meta.state)}"

    /** C Tor `circuit_find_circuits_to_upgrade_from_guard_wait`. */
    fun circuitFindCircuitsToUpgradeFromGuardWait(): List<CircuitMeta> =
        byId.values.filter { it.state == CircuitState.GUARD_WAIT }.toList()

    /** C Tor `circuit_find_to_cannibalize`. */
    fun circuitFindToCannibalize(purpose: CircuitPurpose = CircuitPurpose.GENERAL): CircuitMeta? =
        byId.values.firstOrNull {
            it.isOrigin && !it.markedForClose && it.state == CircuitState.OPEN && it.purpose == purpose
        }

    /** C Tor `circuit_free_`. */
    fun circuitFree(circId: Long): CircuitMeta? = remove(circId)

    /** C Tor `circuit_free_all`. */
    fun circuitFreeAll() = clear()

    /** C Tor `circuit_get_all_pending_on_channel`. */
    fun circuitGetAllPendingOnChannel(channelGid: Long): List<CircuitMeta> =
        byId.values.filter { it.channelGid == channelGid && it.state == CircuitState.CHAN_WAIT }.toList()

    /** C Tor `circuit_get_by_circid_channel`. */
    fun circuitGetByCircidChannel(circId: Long, channelGid: Long): CircuitMeta? {
        val m = byId[circId] ?: return null
        if (m.markedForClose) return null
        if (m.channelGid != 0L && m.channelGid != channelGid) return null
        if (isCircidUnusable(circId)) return null
        return m
    }

    /** C Tor `circuit_get_by_circid_channel_even_if_marked`. */
    fun circuitGetByCircidChannelEvenIfMarked(circId: Long, channelGid: Long): CircuitMeta? {
        val m = byId[circId] ?: return null
        if (m.channelGid != 0L && m.channelGid != channelGid) return null
        return m
    }

    /** C Tor `circuit_get_by_edge_conn`. */
    fun circuitGetByEdgeConn(edgeStreamId: Long): CircuitMeta? =
        byId.values.firstOrNull { it.edgeStreamId == edgeStreamId }

    /** C Tor `circuit_get_by_global_id`. */
    fun circuitGetByGlobalId(globalId: Long): CircuitMeta? = byId[globalId]

    /** C Tor `circuit_get_cpath_hop`. */
    fun circuitGetCpathHop(meta: CircuitMeta, hop: Int): ExtendInfo? =
        meta.cpath.getOrNull(hop)

    /** C Tor `circuit_get_cpath_len`. */
    fun circuitGetCpathLen(meta: CircuitMeta): Int = meta.cpath.size

    /** C Tor `circuit_get_cpath_opened_len`. */
    fun circuitGetCpathOpenedLen(meta: CircuitMeta): Int =
        meta.cpathOpenedLen.coerceIn(0, meta.cpath.size)
}

/** C Tor `circuit_t.state` values used by [CircuitList.stateToString]. */
enum class CircuitState {
    BUILDING,
    ONIONSKIN_PENDING,
    CHAN_WAIT,
    GUARD_WAIT,
    OPEN,
}
