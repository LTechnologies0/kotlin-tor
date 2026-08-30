package org.kotlintor.hs

import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicReference

/**
 * HS common helpers (C Tor `hs_common.c`).
 *
 * Inventory: `L1:feature/hs/hs_common.c`
 *
 * Primary naming file; logic previously lived alongside config/DoS in a shared
 * compilation unit — kept here for inventory/naming parity.
 */
object HsCommon {
    fun timePeriodNum(now: Instant = Instant.now()): Long =
        HsTimePeriod.containing(now).intervalNum

    fun buildBlindedPubkey(identityPublic: ByteArray, period: HsTimePeriod): ByteArray =
        HsKeyBlind.blindPublicKey(identityPublic, period)

    fun hsdirIndexHint(identityHex: String, periodNum: Long, replica: Int): String =
        "$identityHex|$periodNum|$replica"

    /** C Tor `get_time_period_length` — returns minutes (default 1440). */
    const val TIME_PERIOD_LENGTH_MIN: Int = 1440

    fun validatePeriodIndex(periodNum: Long): Boolean = periodNum > 0

    /** Minutes → seconds convenience (not a C Tor alias). */
    fun timePeriodLengthSec(minutes: Int = TIME_PERIOD_LENGTH_MIN): Long =
        minutes.coerceAtLeast(1) * 60L

    /** C Tor `get_time_period_length` — minutes. */
    fun getTimePeriodLength(minutes: Int = TIME_PERIOD_LENGTH_MIN): Long =
        minutes.coerceAtLeast(1).toLong()

    /**
     * C Tor `build_blinded_key_param` — blinding factor param bytes.
     */
    fun buildBlindedKeyParam(
        publicIdentity: ByteArray,
        period: HsTimePeriod,
        secret: ByteArray = ByteArray(0),
    ): ByteArray = HsKeyBlind.blindingFactor(publicIdentity, period, secret)

    private val disasterCache = AtomicReference<Pair<ByteArray, ByteArray>?>(null)

    /** C Tor `get_disaster_srv`. */
    fun getDisasterSrv(period: HsTimePeriod): ByteArray {
        val v = DigestsDisaster.srv(period)
        val cur = disasterCache.get()
        disasterCache.set(
            if (cur == null) v to v else cur.first to v,
        )
        return v
    }

    /** C Tor `get_first_cached_disaster_srv`. */
    fun getFirstCachedDisasterSrv(): ByteArray? = disasterCache.get()?.first

    /** C Tor `get_second_cached_disaster_srv`. */
    fun getSecondCachedDisasterSrv(): ByteArray? = disasterCache.get()?.second

    private val lastHidServRequests = ConcurrentHashMap<String, Long>()

    /** C Tor `get_last_hid_serv_requests`. */
    fun getLastHidServRequests(): Map<String, Long> = LinkedHashMap(lastHidServRequests)

    fun noteHidServRequest(key: String, epochSec: Long = System.currentTimeMillis() / 1000) {
        lastHidServRequests[key] = epochSec
    }

    /** C Tor `hs_address_is_valid`. */
    fun hsAddressIsValid(address: String): Boolean =
        runCatching { OnionAddressV3.decode(address); true }.getOrDefault(false)

    /** C Tor `hs_build_address`. */
    fun hsBuildAddress(publicIdentity: ByteArray): String = OnionAddressV3.encode(publicIdentity)

    /** C Tor `hs_build_blinded_pubkey`. */
    fun hsBuildBlindedPubkey(identityPublic: ByteArray, period: HsTimePeriod): ByteArray =
        buildBlindedPubkey(identityPublic, period)

    /** C Tor `hs_build_blinded_keypair`. */
    fun hsBuildBlindedKeypair(
        privateIdentitySeed: ByteArray,
        publicIdentity: ByteArray,
        period: HsTimePeriod,
    ) = HsKeyBlind.blindSecretKey(privateIdentitySeed, publicIdentity, period)

    /** C Tor `hs_build_hs_index`. */
    fun hsBuildHsIndex(blindedPublic: ByteArray, replica: Long, period: HsTimePeriod): ByteArray =
        HsKeyBlind.serviceIndex(blindedPublic, replica, period)

    /** C Tor `hs_build_hsdir_index`. */
    fun hsBuildHsdirIndex(
        nodeEd25519Identity: ByteArray,
        sharedRandom: ByteArray,
        period: HsTimePeriod,
    ): ByteArray = HsKeyBlind.relayIndex(nodeEd25519Identity, sharedRandom, period)

    /**
     * C Tor `hs_check_service_private_dir` — directory exists and is readable.
     */
    fun hsCheckServicePrivateDir(path: java.nio.file.Path): Boolean =
        java.nio.file.Files.isDirectory(path) && java.nio.file.Files.isReadable(path)

    /** C Tor `hs_clean_last_hid_serv_requests`. */
    fun hsCleanLastHidServRequests(olderThanEpochSec: Long = 0) {
        if (olderThanEpochSec <= 0) {
            lastHidServRequests.clear()
        } else {
            lastHidServRequests.entries.removeIf { it.value < olderThanEpochSec }
        }
    }

    /** C Tor `hs_cleanup_circ` — free circuit map entry by id. */
    fun hsCleanupCirc(circId: Long) {
        HsCircuit.hsCircCleanupOnFree(circId)
        HsCircuitmap.hsCircuitmapRemoveCircuit(circId)
    }

    private val rdvStreamCounter = java.util.concurrent.atomic.AtomicInteger(0)

    /** C Tor `hs_dec_rdv_stream_counter`. */
    fun hsDecRdvStreamCounter(): Int = rdvStreamCounter.updateAndGet { (it - 1).coerceAtLeast(0) }

    fun hsIncRdvStreamCounter(): Int = rdvStreamCounter.incrementAndGet()

    fun hsRdvStreamCounter(): Int = rdvStreamCounter.get()

    /** C Tor defaults for HSDir ring. */
    const val HSDIR_N_REPLICAS: Int = 2
    const val HSDIR_SPREAD_FETCH: Int = 3
    const val HSDIR_SPREAD_STORE: Int = 4

    @Volatile private var currentSrv: ByteArray? = null
    @Volatile private var previousSrv: ByteArray? = null

    /** C Tor `hs_get_current_srv`. */
    fun hsGetCurrentSrv(): ByteArray? = currentSrv

    /** C Tor `hs_get_previous_srv`. */
    fun hsGetPreviousSrv(): ByteArray? = previousSrv

    fun hsSetCurrentSrv(srv: ByteArray?) {
        previousSrv = currentSrv
        currentSrv = srv
    }

    /** C Tor `hs_get_extend_info_from_lspecs` — requires onion/ntor key (C Tor passes it). */
    fun hsGetExtendInfoFromLspecs(
        linkSpecifiers: ByteArray,
        onionKeyNtor: ByteArray,
    ): HsClient.ExtendInfoLite? {
        require(onionKeyNtor.size == 32) { "onion_key must be 32 bytes" }
        val parsed = runCatching { LinkSpecifiers.parsePacked(linkSpecifiers) }.getOrNull()
            ?: return null
        val ipv4 = parsed.ipv4?.joinToString(".") { (it.toInt() and 0xff).toString() }
        return HsClient.ExtendInfoLite(
            identityHex = parsed.legacyId?.let { LinkSpecifiers.fingerprintHex(it) },
            ipv4 = ipv4,
            orPort = parsed.port,
            onionKeyNtor = onionKeyNtor.copyOf(),
        )
    }

    /** C Tor `hs_get_hsdir_n_replicas`. */
    fun hsGetHsdirNReplicas(): Int = HSDIR_N_REPLICAS

    /** C Tor `hs_get_hsdir_spread_fetch`. */
    fun hsGetHsdirSpreadFetch(): Int = HSDIR_SPREAD_FETCH

    /** C Tor `hs_get_hsdir_spread_store`. */
    fun hsGetHsdirSpreadStore(): Int = HSDIR_SPREAD_STORE

    /** C Tor `hs_get_next_time_period_num`. */
    fun hsGetNextTimePeriodNum(now: java.time.Instant = java.time.Instant.now()): Long =
        timePeriodNum(now) + 1

    /** C Tor `hs_get_previous_time_period_num`. */
    fun hsGetPreviousTimePeriodNum(now: java.time.Instant = java.time.Instant.now()): Long =
        (timePeriodNum(now) - 1).coerceAtLeast(0)

    /** C Tor `hs_free_all` — clear process-wide HS client/service/cache/map state. */
    fun hsFreeAll() {
        HsClient.hsClientFreeAll()
        HsService.clearServices()
        HsService.clearStaging()
        HsCircuit.clearAll()
        HsCircuitmap.hsCircuitmapFreeAll()
        HsDos.hsDosInit()
        lastHidServRequests.clear()
        rdvStreamCounter.set(0)
        currentSrv = null
        previousSrv = null
        disasterCache.set(null)
    }
}
