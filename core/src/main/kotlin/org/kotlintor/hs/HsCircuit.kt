package org.kotlintor.hs

import java.util.PriorityQueue
import java.util.concurrent.ConcurrentHashMap

/**
 * HS circuit helpers (C Tor `hs_circuit.c`).
 *
 * Inventory: `L1:feature/hs/hs_circuit.c`
 */
object HsCircuit {
    const val PURPOSE_INTRO_POINT: String = "HS_INTRO_POINT"
    const val PURPOSE_REND_POINT: String = "HS_REND_POINT"
    const val PURPOSE_CLIENT_INTRO: String = "HS_CLIENT_INTRO"
    const val PURPOSE_CLIENT_REND: String = "HS_CLIENT_REND"

    data class RpCircuitId(val cookieHex: String, val circId: Long)

    data class RendPqueueEntry(val dueEpochSec: Long, val circId: Long)

    data class CircLite(
        val circId: Long,
        var purpose: String,
        var open: Boolean = true,
        var rendSentInIntro1: Boolean = false,
        var authKeyHex: String? = null,
    )

    private val rendPqueue = PriorityQueue<RendPqueueEntry>(compareBy { it.dueEpochSec })
    private val byId = ConcurrentHashMap<Long, CircLite>()
    private val establishedIntro = ConcurrentHashMap<String, Long>()
    private val launchSeq = java.util.concurrent.atomic.AtomicLong(1)

    fun purposes(): Set<String> = setOf(
        PURPOSE_INTRO_POINT, PURPOSE_REND_POINT, PURPOSE_CLIENT_INTRO, PURPOSE_CLIENT_REND,
    )

    /** C Tor `create_rp_circuit_identifier`. */
    fun createRpCircuitIdentifier(rendCookie: ByteArray, circId: Long): RpCircuitId {
        require(rendCookie.isNotEmpty())
        val hex = rendCookie.joinToString("") { "%02x".format(it) }
        return RpCircuitId(hex, circId)
    }

    fun rendPqueueOffer(dueEpochSec: Long, circId: Long) {
        rendPqueue.offer(RendPqueueEntry(dueEpochSec, circId))
    }

    /** C Tor `rend_pqueue_clear`. */
    fun rendPqueueClear() {
        rendPqueue.clear()
    }

    /** C Tor `top_of_rend_pqueue_is_worthwhile`. */
    fun topOfRendPqueueIsWorthwhile(nowEpochSec: Long): Boolean {
        val top = rendPqueue.peek() ?: return false
        return top.dueEpochSec <= nowEpochSec
    }

    fun noteCirc(c: CircLite) {
        byId[c.circId] = c
        c.authKeyHex?.let { establishedIntro[it.uppercase()] = c.circId }
    }

    /** C Tor `hs_circ_cleanup_on_close`. */
    fun hsCircCleanupOnClose(circId: Long) {
        byId[circId]?.open = false
    }

    /** C Tor `hs_circ_cleanup_on_free`. */
    fun hsCircCleanupOnFree(circId: Long) {
        val c = byId.remove(circId)
        c?.authKeyHex?.let { establishedIntro.remove(it.uppercase()) }
    }

    /** C Tor `hs_circ_cleanup_on_repurpose`. */
    fun hsCircCleanupOnRepurpose(circId: Long, newPurpose: String) {
        byId[circId]?.let {
            it.purpose = newPurpose
            it.rendSentInIntro1 = false
        }
    }

    /** C Tor `hs_circ_handle_intro_established`. */
    fun hsCircHandleIntroEstablished(circId: Long, authKeyHex: String): Boolean {
        val c = byId[circId] ?: return false
        c.authKeyHex = authKeyHex
        c.purpose = PURPOSE_INTRO_POINT
        establishedIntro[authKeyHex.uppercase()] = circId
        return true
    }

    /** C Tor `hs_circ_handle_introduce2`. */
    fun hsCircHandleIntroduce2(circId: Long, payload: ByteArray): Boolean {
        val c = byId[circId] ?: return false
        if (!c.open || c.purpose != PURPOSE_INTRO_POINT) return false
        return payload.isNotEmpty()
    }

    /** C Tor `hs_circ_is_rend_sent_in_intro1`. */
    fun hsCircIsRendSentInIntro1(circId: Long): Boolean =
        byId[circId]?.rendSentInIntro1 == true

    /** C Tor `hs_circ_launch_intro_point`. */
    fun hsCircLaunchIntroPoint(authKeyHex: String): CircLite {
        val id = launchSeq.getAndIncrement()
        val c = CircLite(id, PURPOSE_INTRO_POINT, authKeyHex = authKeyHex)
        noteCirc(c)
        return c
    }

    /** C Tor `hs_circ_launch_rendezvous_point`. */
    fun hsCircLaunchRendezvousPoint(): CircLite {
        val id = launchSeq.getAndIncrement()
        val c = CircLite(id, PURPOSE_REND_POINT)
        noteCirc(c)
        return c
    }

    /** C Tor `hs_circ_retry_service_rendezvous_point`. */
    fun hsCircRetryServiceRendezvousPoint(oldCircId: Long): CircLite {
        hsCircCleanupOnFree(oldCircId)
        return hsCircLaunchRendezvousPoint()
    }

    /** C Tor `hs_circ_send_establish_rendezvous`. */
    fun hsCircSendEstablishRendezvous(circId: Long, rendCookie: ByteArray): ByteArray {
        val c = byId[circId] ?: error("unknown circ")
        c.purpose = PURPOSE_CLIENT_REND
        return HsCell.hsCellBuildEstablishRendezvous(rendCookie)
    }

    /** C Tor `hs_circ_send_introduce1`. */
    fun hsCircSendIntroduce1(
        circId: Long,
        authKey: ByteArray,
        encryptedBody: ByteArray = ByteArray(0),
    ): ByteArray {
        val c = byId[circId] ?: error("unknown circ")
        c.purpose = PURPOSE_CLIENT_INTRO
        c.rendSentInIntro1 = true
        return HsCell.hsCellBuildIntroduce1(authKey = authKey, encryptedBody = encryptedBody)
    }

    /** C Tor `hs_circ_service_get_established_intro_circ`. */
    fun hsCircServiceGetEstablishedIntroCirc(authKeyHex: String): CircLite? {
        val id = establishedIntro[authKeyHex.uppercase()] ?: return null
        return byId[id]?.takeIf { it.open }
    }

    /** C Tor `hs_circ_service_get_intro_circ` — any intro circ for auth key. */
    fun hsCircServiceGetIntroCirc(authKeyHex: String): CircLite? =
        hsCircServiceGetEstablishedIntroCirc(authKeyHex)
            ?: byId.values.firstOrNull {
                it.authKeyHex.equals(authKeyHex, ignoreCase = true) &&
                    it.purpose == PURPOSE_INTRO_POINT
            }

    /** C Tor `hs_circ_service_intro_has_opened`. */
    fun hsCircServiceIntroHasOpened(circId: Long): Boolean {
        val c = byId[circId] ?: return false
        return c.open && c.purpose == PURPOSE_INTRO_POINT
    }

    /** C Tor `hs_circ_service_rp_has_opened`. */
    fun hsCircServiceRpHasOpened(circId: Long): Boolean {
        val c = byId[circId] ?: return false
        return c.open && c.purpose == PURPOSE_REND_POINT
    }

    /** C Tor `hs_circ_setup_congestion_control` — mark setup done. */
    fun hsCircSetupCongestionControl(circId: Long): Boolean {
        return byId.containsKey(circId)
    }

    /**
     * C Tor `hs_circuit_setup_e2e_rend_circ` — mark client/service rend e2e ready.
     */
    fun hsCircuitSetupE2eRendCirc(circId: Long): Boolean {
        val c = byId[circId] ?: return false
        c.purpose = PURPOSE_CLIENT_REND
        c.open = true
        return true
    }

    /** C Tor `hs_circuit_setup_e2e_rend_circ_legacy_client`. */
    fun hsCircuitSetupE2eRendCircLegacyClient(circId: Long): Boolean =
        hsCircuitSetupE2eRendCirc(circId)

    fun clearAll() {
        byId.clear()
        establishedIntro.clear()
        rendPqueue.clear()
    }
}
