package org.kotlintor.circuit

import java.util.concurrent.ConcurrentHashMap

/**
 * Conflux set pool (C Tor `conflux_pool.c`).
 *
 * Inventory: `L1:core/or/conflux_pool.c`
 *
 * Tracks linked/unlinked sets by nonce; algorithm choice from desired UX.
 */
object ConfluxPool {
    const val ALG_LOWRTT: Int = 1
    const val ALG_MINRTT: Int = 2

    private val linked = ConcurrentHashMap<String, ConfluxUtil.SetState>()
    private val unlinked = ConcurrentHashMap<String, ConfluxUtil.SetState>()
    @Volatile private var initialized = false
    @Volatile private var shuttingDown = false

    fun init() {
        initialized = true
        shuttingDown = false
    }

    fun freeAll() {
        linked.clear()
        unlinked.clear()
        initialized = false
        shuttingDown = false
    }

    fun notifyShutdown() {
        shuttingDown = true
    }

    fun clearShutdown() {
        shuttingDown = false
    }

    fun isInitialized(): Boolean = initialized
    fun isShuttingDown(): Boolean = shuttingDown

    /** C Tor `conflux_choose_algorithm`. */
    fun chooseAlgorithm(desiredUx: ConfluxCell.DesiredUx): Int = when (desiredUx) {
        ConfluxCell.DesiredUx.NO_OPINION,
        ConfluxCell.DesiredUx.HIGH_THROUGHPUT,
        -> ALG_LOWRTT
        ConfluxCell.DesiredUx.MIN_LATENCY,
        ConfluxCell.DesiredUx.LOW_MEM_LATENCY,
        ConfluxCell.DesiredUx.LOW_MEM_THROUGHPUT,
        -> ALG_MINRTT
    }

    fun newSet(nonce: ByteArray = ConfluxCell.newNonce()): ConfluxUtil.SetState {
        require(nonce.size == 32)
        val set = ConfluxUtil.SetState(nonce = nonce.copyOf())
        unlinked[nonceKey(nonce)] = set
        return set
    }

    fun find(nonce: ByteArray): ConfluxUtil.SetState? {
        val k = nonceKey(nonce)
        return linked[k] ?: unlinked[k]
    }

    fun markLinked(set: ConfluxUtil.SetState) {
        val k = nonceKey(set.nonce)
        unlinked.remove(k)
        set.linked = true
        linked[k] = set
    }

    fun markAllForClose(nonce: ByteArray, reason: Int = 0) {
        val set = find(nonce) ?: return
        set.inFullTeardown = true
        set.legs.forEach { it.markedForClose = true; it.canSend = false }
        val k = nonceKey(nonce)
        linked.remove(k)
        unlinked.remove(k)
        @Suppress("UNUSED_VARIABLE")
        val unused = reason
    }

    fun linkedCount(): Int = linked.size
    fun unlinkedCount(): Int = unlinked.size

    /** Cap linked sets using [ConfluxParams.getMaxLinkedSet]. */
    fun canAllocateLinked(): Boolean =
        !shuttingDown && linked.size < ConfluxParams.getMaxLinkedSet()

    /** C Tor `conflux_pool_init`. */
    fun confluxPoolInit() = init()

    /** C Tor `conflux_pool_free_all`. */
    fun confluxPoolFreeAll() = freeAll()

    /** C Tor `conflux_notify_shutdown`. */
    fun confluxNotifyShutdown() = notifyShutdown()

    /** C Tor `conflux_clear_shutdown`. */
    fun confluxClearShutdown() = clearShutdown()

    /** C Tor `conflux_mark_all_for_close`. */
    fun confluxMarkAllForClose(nonce: ByteArray, isClient: Boolean = true) {
        @Suppress("UNUSED_VARIABLE")
        val unused = isClient
        markAllForClose(nonce)
    }

    /** C Tor `conflux_predict_new`. */
    fun confluxPredictNew(nowSec: Long = System.currentTimeMillis() / 1000) {
        @Suppress("UNUSED_VARIABLE")
        val unused = nowSec
        if (shuttingDown || !initialized) return
        // Prebuild is deferred to CircuitUse; mark pool ready.
    }

    /** C Tor `conflux_launch_leg`. */
    fun confluxLaunchLeg(nonce: ByteArray): Boolean {
        if (shuttingDown || !initialized) return false
        val set = find(nonce) ?: return false
        return set.legs.size < ConfluxParams.getMaxLegsSet()
    }

    /** C Tor `launch_new_set`. */
    fun launchNewSet(numLegs: Int): Boolean {
        if (shuttingDown || !canAllocateLinked()) return false
        val set = newSet()
        repeat(numLegs.coerceAtLeast(1)) { i ->
            ConfluxUtil.addLeg(set, circId = (i + 1).toLong())
        }
        return true
    }

    /** C Tor `conflux_add_guards_to_exclude_list`. */
    fun confluxAddGuardsToExcludeList(exclude: MutableSet<String>, digests: Collection<String>) {
        exclude.addAll(digests)
    }

    /** C Tor `conflux_add_middles_to_exclude_list`. */
    fun confluxAddMiddlesToExcludeList(exclude: MutableSet<String>, digests: Collection<String>) {
        exclude.addAll(digests)
    }

    /** C Tor `conflux_circuit_has_closed`. */
    fun confluxCircuitHasClosed(nonce: ByteArray?, circId: Long) {
        if (nonce == null) return
        val set = find(nonce) ?: return
        set.legs.find { it.circId == circId }?.apply {
            canSend = false
            markedForClose = true
        }
    }

    /** C Tor `conflux_circuit_has_opened`. */
    fun confluxCircuitHasOpened(nonce: ByteArray?, circId: Long) {
        if (nonce == null) return
        val set = find(nonce) ?: newSet(nonce)
        ConfluxUtil.addLeg(set, circId)
    }

    /** C Tor `conflux_circuit_about_to_free`. */
    fun confluxCircuitAboutToFree(nonce: ByteArray?, circId: Long) {
        confluxCircuitHasClosed(nonce, circId)
    }

    /** C Tor `conflux_process_link`. */
    fun confluxProcessLink(nonce: ByteArray, circId: Long): Boolean {
        val set = find(nonce) ?: newSet(nonce)
        ConfluxUtil.addLeg(set, circId)
        return true
    }

    /** C Tor `conflux_process_linked`. */
    fun confluxProcessLinked(nonce: ByteArray, circId: Long): Boolean {
        val set = find(nonce) ?: return false
        ConfluxUtil.addLeg(set, circId)
        markLinked(set)
        return true
    }

    /** C Tor `conflux_process_linked_ack`. */
    fun confluxProcessLinkedAck(nonce: ByteArray): Boolean {
        val set = find(nonce) ?: return false
        markLinked(set)
        return true
    }

    /** C Tor `conflux_get_circ_for_conn` — first sendable leg. */
    fun confluxGetCircForConn(nonce: ByteArray?): Long? {
        if (nonce == null) return null
        val set = find(nonce) ?: return null
        return ConfluxUtil.decideNextCirc(set)
    }

    /** C Tor `conflux_log_set`. */
    fun confluxLogSet(set: ConfluxUtil.SetState, isClient: Boolean = true): String {
        @Suppress("UNUSED_VARIABLE")
        val unused = isClient
        return "cfx legs=${set.legs.size} linked=${set.linked} teardown=${set.inFullTeardown}"
    }

    /** C Tor `get_linked_pool` size helper. */
    fun getLinkedPool(): Int = linked.size

    /** C Tor `get_unlinked_pool` size helper. */
    fun getUnlinkedPool(): Int = unlinked.size

    private fun nonceKey(nonce: ByteArray): String =
        nonce.joinToString("") { b -> "%02x".format(b.toInt() and 0xff) }
}
