package org.kotlintor.hs

import java.nio.file.Path
import java.util.concurrent.ConcurrentHashMap

/**
 * OnionBalance frontend helpers (C Tor `hs_ob.c`).
 *
 * Inventory: `L1:feature/hs/hs_ob.c`
 *
 * Implementation: [OnionBalanceFrontend].
 */
object HsOb {
    fun generate(): OnionBalanceFrontend = OnionBalanceFrontend.generate()
    fun load(dir: Path): OnionBalanceFrontend = OnionBalanceFrontend.load(dir)

    /**
     * C Tor `compute_subcredentials` —
     * for each OB master pubkey: subcreds at TP+{0,-1,+1}, then optional instance
     * current/next descriptor subcreds (rend-spec / hs_ob.c).
     *
     * Returns an empty list when [masterPubkeys] is empty (not an OB instance).
     */
    fun computeSubcredentials(
        masterPubkeys: List<ByteArray>,
        timePeriodNum: Long,
        currentInstanceSubcred: ByteArray? = null,
        nextInstanceSubcred: ByteArray? = null,
    ): List<ByteArray> {
        if (masterPubkeys.isEmpty()) return emptyList()
        val steps = intArrayOf(0, -1, 1)
        val out = ArrayList<ByteArray>(steps.size * masterPubkeys.size + 2)
        for (step in steps) {
            for (pkey in masterPubkeys) {
                require(pkey.size == 32) { "master pubkey must be 32 bytes" }
                val period = HsTimePeriod(intervalNum = timePeriodNum + step)
                val blinded = HsKeyBlind.blindPublicKey(pkey, period)
                out += HsKeyBlind.subcredential(pkey, blinded)
            }
        }
        currentInstanceSubcred?.let {
            require(it.size == 32)
            out += it.copyOf()
        }
        nextInstanceSubcred?.let {
            require(it.size == 32)
            out += it.copyOf()
        }
        return out
    }

    /**
     * Single master+blinded pair → one subcredential (helper; not the full OB array).
     * Prefer [computeSubcredentials] with master keys + time period for C Tor parity.
     */
    fun computeSubcredentials(publicIdentity: ByteArray, blindedPublic: ByteArray): ByteArray =
        HsKeyBlind.subcredential(publicIdentity, blindedPublic)

    @Volatile private var loadedFrontend: OnionBalanceFrontend? = null

    /** Onion addresses configured as OB *backend instances* (have ≥1 master pubkey). */
    private val instanceMasterKeys = ConcurrentHashMap<String, List<ByteArray>>()

    /** C Tor `hs_ob_free_all`. */
    fun hsObFreeAll() {
        loadedFrontend = null
        instanceMasterKeys.clear()
    }

    /**
     * Mark a service as an OnionBalance instance (C Tor `ob_master_pubkeys` non-empty).
     */
    fun hsObConfigureInstance(onionAddress: String, masterPubkeys: List<ByteArray>) {
        require(masterPubkeys.isNotEmpty()) { "OB instance needs ≥1 master pubkey" }
        require(masterPubkeys.all { it.size == 32 })
        instanceMasterKeys[onionAddress.lowercase()] = masterPubkeys.map { it.copyOf() }
    }

    /** C Tor `hs_ob_parse_config_file` — treat path as OB key dir if present. */
    fun hsObParseConfigFile(path: Path): OnionBalanceFrontend? =
        runCatching {
            val fe = load(path)
            loadedFrontend = fe
            fe
        }.getOrNull()

    /** C Tor `hs_ob_refresh_keys`. */
    fun hsObRefreshKeys(): OnionBalanceFrontend {
        val fe = generate()
        loadedFrontend = fe
        return fe
    }

    /**
     * C Tor `hs_ob_service_is_instance` —
     * true iff the service has ≥1 OB master ed25519 pubkey configured
     * (frontend address alone is not an instance).
     */
    fun hsObServiceIsInstance(onionAddress: String): Boolean =
        (instanceMasterKeys[onionAddress.lowercase()]?.size ?: 0) > 0

    fun hsObServiceIsInstance(svc: HsService.ServiceLite): Boolean =
        hsObServiceIsInstance(svc.onionAddress)

    fun hsObInstanceMasterKeys(onionAddress: String): List<ByteArray> =
        instanceMasterKeys[onionAddress.lowercase()].orEmpty()
}
