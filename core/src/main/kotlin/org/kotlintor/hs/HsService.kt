package org.kotlintor.hs

import java.util.concurrent.ConcurrentHashMap

/**
 * Naming-parity codefile for C Tor `hs_service.c`.
 *
 * Host lifecycle implementation: [OnionServiceManager] in OnionService.kt.
 */
object HsService {
    const val C_TOR_UNIT: String = "hs_service.c"

    data class ServiceLite(
        val onionAddress: String,
        val directoryHint: String = "",
        val numIntroPoints: Int = 3,
        val introCircuitsReady: Int = 0,
        val descriptors: MutableList<String> = mutableListOf(),
    )

    private val byAddress = ConcurrentHashMap<String, ServiceLite>()

    fun managerTypeName(): String = OnionServiceManager::class.java.name

    fun registerService(svc: ServiceLite) {
        byAddress[svc.onionAddress.lowercase()] = svc
    }

    fun clearServices() {
        byAddress.clear()
    }

    /** C Tor `find_service`. */
    fun findService(onionAddress: String): ServiceLite? =
        byAddress[onionAddress.lowercase()]

    /** C Tor `get_first_service`. */
    fun getFirstService(): ServiceLite? = byAddress.values.firstOrNull()

    /** C Tor `get_hs_service_map`. */
    fun getHsServiceMap(): Map<String, ServiceLite> = LinkedHashMap(byAddress)

    /** C Tor `get_hs_service_map_size`. */
    fun getHsServiceMapSize(): Int = byAddress.size

    private val staging = ArrayList<ServiceLite>()

    /** C Tor `get_hs_service_staging_list_size`. */
    fun getHsServiceStagingListSize(): Int = staging.size

    fun stageService(svc: ServiceLite) {
        staging += svc
    }

    fun clearStaging() {
        staging.clear()
    }

    /**
     * C Tor `get_node_from_intro_point` — fingerprint hex from packed link specs.
     */
    fun getNodeFromIntroPoint(ip: IntroductionPoint): String? {
        val parsed = runCatching { LinkSpecifiers.parsePacked(ip.linkSpecifiers) }.getOrNull()
            ?: return null
        return parsed.legacyId?.let { LinkSpecifiers.fingerprintHex(it) }
    }

    /**
     * C Tor `get_objects_from_ident` — resolve service by identity pubkey
     * (`hs_ident_circuit_t.identity_pk`), not by substring of the onion string.
     *
     * Lookup order: exact [ServiceLite.directoryHint] hex → onion address decode →
     * exact onion address key.
     */
    fun getObjectsFromIdent(ident: HsIdentCircuit): ServiceLite? {
        val hex = ident.serviceIdentityHex?.trim()?.replace(" ", "")?.uppercase() ?: return null
        if (hex.isEmpty()) return null
        byAddress.values.firstOrNull {
            it.directoryHint.replace(" ", "").equals(hex, ignoreCase = true)
        }?.let { return it }
        byAddress.values.firstOrNull { svc ->
            val pk = runCatching { OnionAddressV3.decode(svc.onionAddress) }.getOrNull()
                ?: return@firstOrNull false
            pk.joinToString("") { b -> "%02X".format(b) } == hex
        }?.let { return it }
        return findService(hex)
    }

    /**
     * C Tor `build_all_descriptors` — ensure current + next time-period descriptor
     * stubs exist per service (hs_service.c builds desc_current and desc_next).
     * Returns count of descriptor bodies produced.
     */
    fun buildAllDescriptors(
        period: HsTimePeriod = HsTimePeriod(intervalNum = 1L),
    ): Int {
        var n = 0
        for (svc in byAddress.values) {
            svc.descriptors.clear()
            val currentTp = period.intervalNum
            val nextTp = period.intervalNum + 1
            for (tp in longArrayOf(currentTp, nextTp)) {
                // DESC-OUTER fields only (no invented time-period keyword).
                svc.descriptors +=
                    "hs-descriptor 3\ndescriptor-lifetime 180\nrevision-counter $tp\n"
                n++
            }
        }
        return n
    }

    /** C Tor `can_service_launch_intro_circuit`. */
    fun canServiceLaunchIntroCircuit(svc: ServiceLite): Boolean =
        svc.introCircuitsReady < svc.numIntroPoints.coerceIn(1, 20)

    /** C Tor `client_filename_is_valid` — authorized_clients entry basename. */
    fun clientFilenameIsValid(name: String): Boolean {
        if (name.contains('/') || name.contains('\\')) return false
        if (!name.endsWith(".auth")) return false
        val stem = name.removeSuffix(".auth")
        if (stem.isEmpty() || stem.length > 64) return false
        return stem.all { it.isLetterOrDigit() || it == '-' || it == '_' }
    }

    private val ephemeral = ConcurrentHashMap<String, ServiceLite>()
    private val serviceCircs = ConcurrentHashMap<Long, String>()
    @Volatile private var initialized: Boolean = false
    @Volatile private var dirInfoEpoch: Long = 0
    @Volatile private var allowNonAnonymous: Boolean = false

    /** C Tor `hs_service_init`. */
    fun hsServiceInit() {
        initialized = true
        clearStaging()
    }

    /** C Tor `hs_service_find`. */
    fun hsServiceFind(onionAddress: String): ServiceLite? = findService(onionAddress)

    /** C Tor `hs_service_free_`. */
    fun hsServiceFree_(svc: ServiceLite?): ServiceLite? {
        svc?.let { byAddress.remove(it.onionAddress.lowercase()) }
        return null
    }

    /** C Tor `hs_service_free_all`. */
    fun hsServiceFreeAll() {
        clearServices()
        clearStaging()
        ephemeral.clear()
        serviceCircs.clear()
        initialized = false
    }

    /** C Tor `hs_service_add_ephemeral`. */
    fun hsServiceAddEphemeral(onionAddress: String, directoryHint: String = ""): ServiceLite {
        val svc = ServiceLite(onionAddress, directoryHint)
        ephemeral[onionAddress.lowercase()] = svc
        registerService(svc)
        return svc
    }

    /** C Tor `hs_service_del_ephemeral`. */
    fun hsServiceDelEphemeral(onionAddress: String): Boolean {
        ephemeral.remove(onionAddress.lowercase())
        return byAddress.remove(onionAddress.lowercase()) != null
    }

    /** C Tor `hs_service_allow_non_anonymous_connection` — query option (not a setter). */
    fun hsServiceAllowNonAnonymousConnection(): Boolean = allowNonAnonymous

    /** Test/config helper to set SingleHop/non-anonymous mode. */
    fun hsServiceSetAllowNonAnonymousConnection(allow: Boolean) {
        allowNonAnonymous = allow
    }

    /** C Tor `hs_service_circuit_has_opened`. */
    fun hsServiceCircuitHasOpened(circId: Long, onionAddress: String): Boolean {
        serviceCircs[circId] = onionAddress.lowercase()
        findService(onionAddress)?.let {
            byAddress[onionAddress.lowercase()] = it.copy(introCircuitsReady = it.introCircuitsReady + 1)
        }
        return true
    }

    /** C Tor `hs_service_circuit_cleanup_on_close`. */
    fun hsServiceCircuitCleanupOnClose(circId: Long): Boolean =
        serviceCircs.remove(circId) != null

    /** C Tor `hs_service_dir_info_changed`. */
    fun hsServiceDirInfoChanged() {
        dirInfoEpoch++
    }

    fun hsServiceDirInfoEpoch(): Long = dirInfoEpoch

    /** C Tor `hs_service_dump_stats`. */
    fun hsServiceDumpStats(): String =
        "services=${byAddress.size} ephemeral=${ephemeral.size} circs=${serviceCircs.size} dirEpoch=$dirInfoEpoch"

    enum class CircuitIdExport { NONE, HAPROXY }

    private val circuitIdExport = ConcurrentHashMap<String, CircuitIdExport>()

    /** C Tor `hs_service_exports_circuit_id` — protocol enum from config. */
    fun hsServiceExportsCircuitId(onionAddress: String): CircuitIdExport =
        circuitIdExport[onionAddress.lowercase()] ?: CircuitIdExport.NONE

    fun hsServiceSetExportsCircuitId(onionAddress: String, proto: CircuitIdExport) {
        circuitIdExport[onionAddress.lowercase()] = proto
    }

    /** C Tor `hs_service_get_metrics_stores`. */
    fun hsServiceGetMetricsStores(): Map<String, Map<String, Int>> =
        HsMetrics.hsMetricsGetStores()

    /** C Tor `hs_service_get_version_from_key` — probe on-disk / key blob for v3. */
    fun hsServiceGetVersionFromKey(keyBytes: ByteArray): Int {
        if (keyBytes.isEmpty()) return -1
        // C Tor `== ed25519v1-secret:` file header (optional) + 32-byte seed.
        val ascii = keyBytes.decodeToString(throwOnInvalidSequence = false)
        if (ascii.contains("ed25519v1-secret") || ascii.contains("== ed25519v1")) return 3
        if (keyBytes.size == 32 || keyBytes.size == 64) return 3
        if (keyBytes.size > 32 && keyBytes.copyOfRange(0, 29)
                .contentEquals("== ed25519v1-secret: type0 ==".toByteArray().copyOf(29))
        ) {
            return 3
        }
        return -1
    }

    /** Path-based probe matching C Tor `service_key_on_disk`. */
    fun hsServiceGetVersionFromKey(directory: java.nio.file.Path): Int {
        val key = directory.resolve("hs_ed25519_secret_key")
        if (!java.nio.file.Files.isRegularFile(key)) return -1
        return hsServiceGetVersionFromKey(java.nio.file.Files.readAllBytes(key))
    }

    /** C Tor `hs_service_lists_fnames_for_sandbox`. */
    fun hsServiceListsFnamesForSandbox(svc: ServiceLite): List<String> =
        listOf(
            "${svc.directoryHint.ifBlank { "." }}/hs_ed25519_secret_key",
            "${svc.directoryHint.ifBlank { "." }}/hs_ed25519_public_key",
            "${svc.directoryHint.ifBlank { "." }}/hostname",
        )

    fun hsServiceInitialized(): Boolean = initialized
}
