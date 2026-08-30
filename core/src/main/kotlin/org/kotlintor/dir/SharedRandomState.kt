package org.kotlintor.dir

import java.nio.file.Path
import java.util.concurrent.atomic.AtomicReference

/**
 * Shared-random persistent state (C Tor `shared_random_state.c`).
 *
 * Inventory: `L1:feature/dirauth/shared_random_state.c`
 *
 * Disk helpers live on [SharedRandom.State]; this object tracks protocol phase.
 */
object SharedRandomState {
    data class ProtocolState(
        val state: SharedRandom.State = SharedRandom.State(),
        @Volatile var phase: SharedRandom.Phase = SharedRandom.Phase.COMMIT,
        @Volatile var validUntilEpochSec: Long = 0,
        @Volatile var initialized: Boolean = false,
        @Volatile var freshSrv: Boolean = false,
    )

    private val global = AtomicReference(ProtocolState())

    fun save(state: SharedRandom.State, path: Path) {
        state.save(path)
    }

    fun load(state: SharedRandom.State, path: Path) {
        state.load(path)
    }

    /** C Tor `get_sr_state`. */
    fun getSrState(): ProtocolState = global.get()

    /** C Tor `disk_state_load_from_disk_impl`. */
    fun diskStateLoadFromDiskImpl(path: Path): ProtocolState {
        val ps = global.get()
        load(ps.state, path)
        ps.initialized = true
        return ps
    }

    /** C Tor `get_sr_protocol_phase` / `sr_state_get_phase`. */
    fun getSrProtocolPhase(ps: ProtocolState = getSrState()): SharedRandom.Phase = ps.phase

    fun srStateGetPhase(ps: ProtocolState = getSrState()): SharedRandom.Phase = getSrProtocolPhase(ps)

    /** C Tor `set_sr_phase`. */
    fun setSrPhase(phase: SharedRandom.Phase, ps: ProtocolState = getSrState()) {
        ps.phase = phase
    }

    /** C Tor `get_phase_str`. */
    fun getPhaseStr(phase: SharedRandom.Phase = getSrProtocolPhase()): String =
        when (phase) {
            SharedRandom.Phase.COMMIT -> "commit"
            SharedRandom.Phase.REVEAL -> "reveal"
        }

    /** C Tor `get_state_valid_until_time`. */
    fun getStateValidUntilTime(ps: ProtocolState = getSrState()): Long = ps.validUntilEpochSec

    fun setStateValidUntilTime(epochSec: Long, ps: ProtocolState = getSrState()) {
        ps.validUntilEpochSec = epochSec
    }

    /** C Tor `is_phase_transition` — true when [now] crosses into next phase window. */
    fun isPhaseTransition(
        nowEpochSec: Long,
        commitEndsEpochSec: Long,
        ps: ProtocolState = getSrState(),
    ): Boolean {
        val next = if (nowEpochSec >= commitEndsEpochSec) {
            SharedRandom.Phase.REVEAL
        } else {
            SharedRandom.Phase.COMMIT
        }
        if (next == ps.phase) return false
        ps.phase = next
        return true
    }

    /** C Tor `new_protocol_run` / `reset_state_for_new_protocol_run`. */
    fun newProtocolRun(validUntilEpochSec: Long = 0): ProtocolState {
        val ps = ProtocolState(validUntilEpochSec = validUntilEpochSec, initialized = true)
        global.set(ps)
        return ps
    }

    fun resetStateForNewProtocolRun(validUntilEpochSec: Long = 0): ProtocolState =
        newProtocolRun(validUntilEpochSec)

    fun srStateIsInitialized(ps: ProtocolState = getSrState()): Boolean = ps.initialized

    fun srStateInit(): ProtocolState {
        val ps = getSrState()
        ps.initialized = true
        return ps
    }

    /** C Tor `sr_state_add_commit`. */
    fun srStateAddCommit(commit: SharedRandom.Commit, ps: ProtocolState = getSrState()) {
        ps.state.put(commit)
    }

    /** C Tor `sr_state_clean_srvs` — drop SRVs when not fresh. */
    fun srStateCleanSrvs(ps: ProtocolState = getSrState()) {
        if (!ps.freshSrv) {
            ps.state.currentSrv = null
            ps.state.previousSrv = null
        }
        ps.freshSrv = false
    }

    /** C Tor `sr_state_copy_reveal_info` — ensure reveal present on stored commit. */
    fun srStateCopyRevealInfo(
        from: SharedRandom.Commit,
        identityHex: String,
        ps: ProtocolState = getSrState(),
    ): Boolean {
        val existing = ps.state.get(identityHex) ?: return false
        if (!from.commitHasRevealValue()) return false
        ps.state.put(from.copy(rsaIdentity = existing.rsaIdentity.copyOf()))
        return true
    }

    /** C Tor `sr_state_delete_commits`. */
    fun srStateDeleteCommits(ps: ProtocolState = getSrState()) {
        ps.state.deleteAll()
    }

    /** C Tor `sr_state_free_all`. */
    fun srStateFreeAll() {
        global.set(ProtocolState())
    }

    /** C Tor `sr_state_get_commit`. */
    fun srStateGetCommit(identityHex: String, ps: ProtocolState = getSrState()): SharedRandom.Commit? =
        ps.state.get(identityHex)

    /** C Tor `sr_state_get_commits`. */
    fun srStateGetCommits(ps: ProtocolState = getSrState()): List<SharedRandom.Commit> = ps.state.all()

    /** C Tor `sr_state_get_current_srv`. */
    fun srStateGetCurrentSrv(ps: ProtocolState = getSrState()): SharedRandom.Srv? = ps.state.currentSrv

    /** C Tor `sr_state_get_previous_srv`. */
    fun srStateGetPreviousSrv(ps: ProtocolState = getSrState()): SharedRandom.Srv? = ps.state.previousSrv

    /** C Tor `sr_state_save`. */
    fun srStateSave(path: Path, ps: ProtocolState = getSrState()) {
        save(ps.state, path)
    }

    /** C Tor `sr_state_set_current_srv`. */
    fun srStateSetCurrentSrv(srv: SharedRandom.Srv?, ps: ProtocolState = getSrState()) {
        ps.state.currentSrv = srv
    }

    /** C Tor `sr_state_set_previous_srv`. */
    fun srStateSetPreviousSrv(srv: SharedRandom.Srv?, ps: ProtocolState = getSrState()) {
        ps.state.previousSrv = srv
    }

    /** C Tor `sr_state_set_fresh_srv`. */
    fun srStateSetFreshSrv(fresh: Boolean, ps: ProtocolState = getSrState()) {
        ps.freshSrv = fresh
    }
}
