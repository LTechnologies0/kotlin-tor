package org.kotlintor.control

import java.nio.file.Path
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * GETINFO key catalog + helpers (C Tor `control_getinfo.c`).
 *
 * Inventory: `L1:feature/control/control_getinfo.c`
 */
object ControlGetinfo {
    val KEYS: Set<String> = setOf(
        "version",
        "status/bootstrap-phase",
        "status/circuit-established",
        "circuit-status",
        "net/listeners/socks",
        "net/listeners/control",
        "config-file",
        "exit-policy/default",
        "onions/current",
        "onions/detached",
        "entry-guards",
        "network-liveness",
        "downloads/networkstatus",
        "downloads/cert",
        "downloads/desc",
        "downloads/bridge",
        "current-time/local",
        "current-time/utc",
    )

    private val downloadStatus = ConcurrentHashMap<String, String>()
    private val detachedOnions = CopyOnWriteArrayList<String>()
    private val networkLiveness = AtomicBoolean(true)
    private val cookieFile = AtomicReference<Path?>(null)
    private val consensusDigest = AtomicReference("0".repeat(40))

    fun isRecognized(key: String): Boolean =
        key in KEYS ||
            key.startsWith("config/", ignoreCase = true) ||
            key.startsWith("ip-to-country/", ignoreCase = true)

    fun configKey(key: String): String? =
        if (key.startsWith("config/", ignoreCase = true)) key.removePrefix("config/") else null

    /** C Tor `getinfo_helper_current_time`. */
    fun getinfoHelperCurrentTime(utc: Boolean = true): String =
        Instant.now().toString()

    /** C Tor `getinfo_helper_current_consensus`. */
    fun getinfoHelperCurrentConsensus(): String = consensusDigest.get()

    fun setCurrentConsensusDigest(hex: String) {
        consensusDigest.set(hex)
    }

    /** C Tor `getinfo_helper_dir`. */
    fun getinfoHelperDir(question: String): String? =
        when {
            question.startsWith("dir/") -> "not-implemented"
            else -> null
        }

    /** C Tor `getinfo_helper_downloads` / download subtypes. */
    fun getinfoHelperDownloads(kind: String = "networkstatus"): String =
        downloadStatus[kind] ?: "unknown"

    fun getinfoHelperDownloadsNetworkstatus(): String = getinfoHelperDownloads("networkstatus")

    fun getinfoHelperDownloadsCert(): String = getinfoHelperDownloads("cert")

    fun getinfoHelperDownloadsDesc(): String = getinfoHelperDownloads("desc")

    fun getinfoHelperDownloadsBridge(): String = getinfoHelperDownloads("bridge")

    fun setDownloadStatus(kind: String, status: String) {
        downloadStatus[kind] = status
    }

    /** C Tor `getinfo_helper_geoip`. */
    fun getinfoHelperGeoip(address: String): String = GetinfoGeoip.countryForAddress(address)

    /** C Tor `getinfo_helper_onions`. */
    fun getinfoHelperOnions(detached: Boolean = false): List<String> =
        if (detached) detachedOnions.toList() else emptyList()

    fun addDetachedOnion(serviceId: String) {
        if (serviceId !in detachedOnions) detachedOnions += serviceId
    }

    /** C Tor `get_detached_onion_services`. */
    fun getDetachedOnionServices(): List<String> = detachedOnions.toList()

    /** C Tor `getinfo_helper_rephist`. */
    fun getinfoHelperRephist(question: String): String = "0"

    /** C Tor `get_cached_network_liveness`. */
    fun getCachedNetworkLiveness(): Boolean = networkLiveness.get()

    /** C Tor `set_cached_network_liveness`. */
    fun setCachedNetworkLiveness(live: Boolean) {
        networkLiveness.set(live)
    }

    /** C Tor `get_controller_cookie_file_name`. */
    fun getControllerCookieFileName(): Path? = cookieFile.get()

    fun setControllerCookieFileName(path: Path?) {
        cookieFile.set(path)
    }
}
