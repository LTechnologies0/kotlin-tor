package org.kotlintor.hs

import org.kotlintor.dir.Consensus
import org.kotlintor.util.concat
import java.util.concurrent.ConcurrentHashMap

/**
 * HS v3 client helpers (C Tor `hs_client.c` subset: onion host / TP / SRV).
 *
 * Inventory: `L1:feature/hs/hs_client.c`
 *
 * Circuit INTRODUCE/REND path: [OnionClient].
 */
object HsClient {
    data class ClientAuth(val onionAddress: String, val clientSecret: ByteArray? = null)

    data class ExtendInfoLite(
        val identityHex: String?,
        val ipv4: String?,
        val orPort: Int?,
        val onionKeyNtor: ByteArray,
    )

    private val clientAuths = ConcurrentHashMap<String, ClientAuth>()

    fun isOnionHost(host: String): Boolean = host.lowercase().endsWith(".onion")

    fun timePeriodForConsensus(consensus: Consensus): HsTimePeriod {
        val length = consensus.param("hsdir-interval", HsTimePeriod.DEFAULT_LENGTH_MINUTES)
        return HsTimePeriod.containing(consensus.validAfter, lengthMinutes = length)
    }

    /**
     * Client SRV selection (rend-spec FETCHUPLOADDESC).
     * Between a new SRV (00:00) and the next TP (12:00) use previous SRV;
     * between TP (12:00) and the next SRV (00:00) use current SRV.
     */
    fun sharedRandomForFetch(consensus: Consensus, period: HsTimePeriod): ByteArray {
        val hour = consensus.validAfter.atZone(java.time.ZoneOffset.UTC).hour
        val preferPrevious = hour < 12
        val primary = if (preferPrevious) consensus.sharedRandPrevious else consensus.sharedRandCurrent
        val secondary = if (preferPrevious) consensus.sharedRandCurrent else consensus.sharedRandPrevious
        return primary ?: secondary ?: DigestsDisaster.srv(period)
    }

    /** Both SRVs to try when the primary HSDir set returns 404. */
    fun sharedRandomCandidates(consensus: Consensus, period: HsTimePeriod): List<ByteArray> {
        val primary = sharedRandomForFetch(consensus, period)
        val out = mutableListOf(primary)
        val other = listOfNotNull(consensus.sharedRandCurrent, consensus.sharedRandPrevious)
            .firstOrNull { !it.contentEquals(primary) }
        if (other != null) out += other
        return out
    }

    /**
     * Service SRV for upload (rend-spec SERVICEUPLOAD / FETCHUPLOADDESC).
     * Between TP (12:00) and next SRV (00:00) prefer current; otherwise previous.
     */
    fun sharedRandomForUpload(consensus: Consensus, period: HsTimePeriod): ByteArray {
        val hour = consensus.validAfter.atZone(java.time.ZoneOffset.UTC).hour
        val preferCurrent = hour >= 12
        val primary = if (preferCurrent) consensus.sharedRandCurrent else consensus.sharedRandPrevious
        val secondary = if (preferCurrent) consensus.sharedRandPrevious else consensus.sharedRandCurrent
        return primary ?: secondary ?: DigestsDisaster.srv(period)
    }

    /** C Tor `auth_key_filename_is_valid` — client auth key basename. */
    fun authKeyFilenameIsValid(name: String): Boolean {
        if (name.contains('/') || name.contains('\\')) return false
        if (name.isEmpty() || name.length > 128) return false
        if (name == "." || name == "..") return false
        return name.all { it.isLetterOrDigit() || it == '.' || it == '-' || it == '_' }
    }

    /** C Tor `client_get_random_intro`. */
    fun clientGetRandomIntro(intros: List<IntroductionPoint>): IntroductionPoint? =
        intros.randomOrNull()

    /** C Tor `client_service_authorization_free_`. */
    fun clientServiceAuthorizationFree_(auth: ClientAuth?): ClientAuth? {
        if (auth != null) clientAuths.remove(auth.onionAddress.lowercase())
        return null
    }

    fun noteClientAuth(auth: ClientAuth) {
        clientAuths[auth.onionAddress.lowercase()] = auth
    }

    /** C Tor `get_hs_client_auths_map`. */
    fun getHsClientAuthsMap(): Map<String, ClientAuth> = LinkedHashMap(clientAuths)

    /** C Tor `desc_intro_point_to_extend_info`. */
    fun descIntroPointToExtendInfo(ip: IntroductionPoint): ExtendInfoLite {
        val parsed = runCatching { LinkSpecifiers.parsePacked(ip.linkSpecifiers) }.getOrNull()
        val ipv4 = parsed?.ipv4?.joinToString(".") { (it.toInt() and 0xff).toString() }
        return ExtendInfoLite(
            identityHex = parsed?.legacyId?.let { LinkSpecifiers.fingerprintHex(it) },
            ipv4 = ipv4,
            orPort = parsed?.port,
            onionKeyNtor = ip.onionKeyNtor,
        )
    }

    /** C Tor `find_desc_intro_point_by_ident`. */
    fun findDescIntroPointByIdent(
        intros: List<IntroductionPoint>,
        authKeyHex: String,
    ): IntroductionPoint? {
        val want = authKeyHex.lowercase()
        return intros.firstOrNull { ip ->
            runCatching {
                ip.authKey.joinToString("") { "%02x".format(it) }.equals(want, ignoreCase = true)
            }.getOrDefault(false)
        }
    }

    /**
     * C Tor `handle_rendezvous2` — accept RENDEZVOUS2 payload length check.
     * Returns true when handshake blob looks non-empty.
     */
    fun handleRendezvous2(payload: ByteArray): Boolean = payload.isNotEmpty()

    data class ClientCirc(
        val circId: Long,
        var open: Boolean = true,
        var purpose: String = HsCircuit.PURPOSE_CLIENT_INTRO,
        var onionAddress: String? = null,
    )

    private val clientCircs = ConcurrentHashMap<Long, ClientCirc>()
    private val pendingFetches = ConcurrentHashMap<String, Boolean>()
    private val connSuccess = ConcurrentHashMap<String, Long>()
    @Volatile private var dirInfoEpoch: Long = 0

    /** C Tor `hs_client_any_intro_points_usable`. */
    fun hsClientAnyIntroPointsUsable(intros: List<IntroductionPoint>): Boolean =
        intros.any { it.onionKeyNtor.size == 32 && it.linkSpecifiers.isNotEmpty() }

    /** C Tor `hs_client_circuit_cleanup_on_close`. */
    fun hsClientCircuitCleanupOnClose(circId: Long) {
        clientCircs[circId]?.open = false
    }

    /** C Tor `hs_client_circuit_cleanup_on_free`. */
    fun hsClientCircuitCleanupOnFree(circId: Long) {
        clientCircs.remove(circId)
    }

    /** C Tor `hs_client_circuit_has_opened`. */
    fun hsClientCircuitHasOpened(circId: Long): Boolean =
        clientCircs[circId]?.open == true

    fun noteClientCirc(c: ClientCirc) {
        clientCircs[c.circId] = c
    }

    /** C Tor `hs_client_close_intro_circuits_from_desc`. */
    fun hsClientCloseIntroCircuitsFromDesc(onionAddress: String): Int {
        var n = 0
        for ((id, c) in clientCircs) {
            if (c.onionAddress.equals(onionAddress, ignoreCase = true) &&
                c.purpose == HsCircuit.PURPOSE_CLIENT_INTRO
            ) {
                c.open = false
                n++
            }
        }
        return n
    }

    /** C Tor `hs_client_decode_descriptor` — parse outer layer only. */
    fun hsClientDecodeDescriptor(document: String): HsDescriptorOuter? =
        runCatching { HsDescriptorCodec.parseOuter(document) }.getOrNull()

    /** C Tor `hs_client_dir_fetch_done`. */
    fun hsClientDirFetchDone(onionAddress: String, success: Boolean) {
        pendingFetches.remove(onionAddress.lowercase())
        if (success) connSuccess[onionAddress.lowercase()] = System.currentTimeMillis() / 1000
    }

    /** C Tor `hs_client_dir_info_changed`. */
    fun hsClientDirInfoChanged() {
        dirInfoEpoch++
    }

    fun dirInfoEpoch(): Long = dirInfoEpoch

    /** C Tor `hs_client_free_all`. */
    fun hsClientFreeAll() {
        clientAuths.clear()
        clientCircs.clear()
        pendingFetches.clear()
        connSuccess.clear()
        dirInfoEpoch = 0
    }

    /** C Tor `hs_client_get_random_intro_from_edge` — alias of random intro. */
    fun hsClientGetRandomIntroFromEdge(intros: List<IntroductionPoint>): IntroductionPoint? =
        clientGetRandomIntro(intros)

    /** C Tor `hs_client_launch_v3_desc_fetch`. */
    fun hsClientLaunchV3DescFetch(onionAddress: String): Boolean {
        val key = onionAddress.lowercase()
        if (pendingFetches.containsKey(key)) return false
        pendingFetches[key] = true
        return true
    }

    /** C Tor `hs_client_note_connection_attempt_succeeded`. */
    fun hsClientNoteConnectionAttemptSucceeded(onionAddress: String) {
        connSuccess[onionAddress.lowercase()] = System.currentTimeMillis() / 1000
    }

    /** C Tor `hs_client_purge_state`. */
    fun hsClientPurgeState() {
        pendingFetches.clear()
        connSuccess.clear()
        clientCircs.clear()
    }

    /** C Tor `hs_client_receive_introduce_ack`. */
    fun hsClientReceiveIntroduceAck(payload: ByteArray): Boolean =
        HsCell.hsCellParseIntroduceAck(payload) == 0

    /** C Tor `hs_client_receive_rendezvous2`. */
    fun hsClientReceiveRendezvous2(payload: ByteArray): Boolean =
        HsCell.hsCellParseRendezvous2(payload) != null

    /** C Tor `hs_client_receive_rendezvous_acked`. */
    fun hsClientReceiveRendezvousAcked(payload: ByteArray): Boolean =
        payload.isEmpty() || (payload[0].toInt() and 0xff) == 0

    /** C Tor `hs_client_reextend_intro_circuit`. */
    fun hsClientReextendIntroCircuit(circId: Long): Boolean {
        val c = clientCircs[circId] ?: return false
        if (!c.open) return false
        c.purpose = HsCircuit.PURPOSE_CLIENT_INTRO
        return true
    }

    /** C Tor `hs_client_refetch_hsdesc`. */
    fun hsClientRefetchHsdesc(onionAddress: String): Boolean {
        pendingFetches.remove(onionAddress.lowercase())
        return hsClientLaunchV3DescFetch(onionAddress)
    }

    fun pendingFetchCount(): Int = pendingFetches.size
}

/** Disaster SRV when consensus SRVs are missing (rend-spec). */
internal object DigestsDisaster {
    fun srv(period: HsTimePeriod): ByteArray =
        org.kotlintor.crypto.Digests.sha3_256(
            concat(
                "shared-random-disaster".toByteArray(),
                org.kotlintor.util.u64be(period.lengthMinutes),
                org.kotlintor.util.u64be(period.intervalNum),
            ),
        )
}
