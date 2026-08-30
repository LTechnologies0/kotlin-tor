package org.kotlintor.hs

import java.util.concurrent.ConcurrentHashMap

/**
 * HS circuit map (C Tor `hs_circuitmap.c`).
 *
 * Inventory: `L1:feature/hs/hs_circuitmap.c`
 */
object HsCircuitmap {
    private val byToken = ConcurrentHashMap<String, Long>()
    private val introRelay = ConcurrentHashMap<String, Long>()
    private val introService = ConcurrentHashMap<String, Long>()
    private val rendClient = ConcurrentHashMap<String, Long>()
    private val rendRelay = ConcurrentHashMap<String, Long>()
    private val rendService = ConcurrentHashMap<String, Long>()
    private val establishedRendClient = ConcurrentHashMap<String, Long>()

    fun put(token: String, circId: Long) { byToken[token] = circId }
    fun get(token: String): Long? = byToken[token]
    fun remove(token: String): Long? = byToken.remove(token)
    fun clear() = byToken.clear()
    fun size(): Int = byToken.size

    /** C Tor `get_hs_circuitmap`. */
    fun getHsCircuitmap(): Map<String, Long> = LinkedHashMap(byToken)

    /** C Tor `hs_circuitmap_init`. */
    fun hsCircuitmapInit() {
        hsCircuitmapFreeAll()
    }

    /** C Tor `hs_circuitmap_free_all`. */
    fun hsCircuitmapFreeAll() {
        byToken.clear()
        introRelay.clear()
        introService.clear()
        rendClient.clear()
        rendRelay.clear()
        rendService.clear()
        establishedRendClient.clear()
    }

    /** C Tor `hs_circuitmap_register_intro_circ_v3_relay_side`. */
    fun hsCircuitmapRegisterIntroCircV3RelaySide(authKeyHex: String, circId: Long) {
        introRelay[authKeyHex.uppercase()] = circId
        byToken["intro-relay:${authKeyHex.uppercase()}"] = circId
    }

    /** C Tor `hs_circuitmap_register_intro_circ_v3_service_side`. */
    fun hsCircuitmapRegisterIntroCircV3ServiceSide(authKeyHex: String, circId: Long) {
        introService[authKeyHex.uppercase()] = circId
        byToken["intro-svc:${authKeyHex.uppercase()}"] = circId
    }

    /** C Tor `hs_circuitmap_get_intro_circ_v3_relay_side`. */
    fun hsCircuitmapGetIntroCircV3RelaySide(authKeyHex: String): Long? =
        introRelay[authKeyHex.uppercase()]

    /** C Tor `hs_circuitmap_get_intro_circ_v3_service_side`. */
    fun hsCircuitmapGetIntroCircV3ServiceSide(authKeyHex: String): Long? =
        introService[authKeyHex.uppercase()]

    /** C Tor `hs_circuitmap_get_all_intro_circ_relay_side`. */
    fun hsCircuitmapGetAllIntroCircRelaySide(): Map<String, Long> = LinkedHashMap(introRelay)

    /** C Tor `hs_circuitmap_register_rend_circ_client_side`. */
    fun hsCircuitmapRegisterRendCircClientSide(cookieHex: String, circId: Long) {
        rendClient[cookieHex.lowercase()] = circId
        byToken["rend-client:${cookieHex.lowercase()}"] = circId
    }

    /** C Tor `hs_circuitmap_register_rend_circ_relay_side`. */
    fun hsCircuitmapRegisterRendCircRelaySide(cookieHex: String, circId: Long) {
        rendRelay[cookieHex.lowercase()] = circId
        byToken["rend-relay:${cookieHex.lowercase()}"] = circId
    }

    /** C Tor `hs_circuitmap_register_rend_circ_service_side`. */
    fun hsCircuitmapRegisterRendCircServiceSide(cookieHex: String, circId: Long) {
        rendService[cookieHex.lowercase()] = circId
        byToken["rend-svc:${cookieHex.lowercase()}"] = circId
    }

    /** C Tor `hs_circuitmap_get_rend_circ_client_side`. */
    fun hsCircuitmapGetRendCircClientSide(cookieHex: String): Long? =
        rendClient[cookieHex.lowercase()]

    /** C Tor `hs_circuitmap_get_rend_circ_relay_side`. */
    fun hsCircuitmapGetRendCircRelaySide(cookieHex: String): Long? =
        rendRelay[cookieHex.lowercase()]

    /** C Tor `hs_circuitmap_get_rend_circ_service_side`. */
    fun hsCircuitmapGetRendCircServiceSide(cookieHex: String): Long? =
        rendService[cookieHex.lowercase()]

    /** C Tor `hs_circuitmap_get_established_rend_circ_client_side`. */
    fun hsCircuitmapGetEstablishedRendCircClientSide(cookieHex: String): Long? =
        establishedRendClient[cookieHex.lowercase()]
            ?: rendClient[cookieHex.lowercase()]?.also {
                establishedRendClient[cookieHex.lowercase()] = it
            }

    /** C Tor `hs_circuitmap_remove_circuit`. */
    fun hsCircuitmapRemoveCircuit(circId: Long) {
        fun purge(map: ConcurrentHashMap<String, Long>) {
            map.entries.removeIf { it.value == circId }
        }
        purge(introRelay); purge(introService)
        purge(rendClient); purge(rendRelay); purge(rendService)
        purge(establishedRendClient)
        byToken.entries.removeIf { it.value == circId }
    }
}
