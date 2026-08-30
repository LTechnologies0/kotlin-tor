package org.kotlintor.config

import java.nio.file.Path
import org.kotlintor.util.writeTextCompat

/**
 * Process / misc torrc options (C Tor `or_options_t` process + client prefs subset).
 */
data class ProcessOptions(
    val pidFile: Path? = null,
    val runAsDaemon: Boolean = false,
    val user: String? = null,
    val numCpus: Int = 0, // 0 = auto (availableProcessors)
    val offlineMasterKey: Boolean = false,
    val onionKeyGracePeriodDays: Int = 7,
    val signingKeyLifetimeDays: Int = 30,
    val shutdownWaitLengthSec: Long = 30,
    val noExec: Boolean = false,
    val constrainedSockets: Boolean = false,
    val constrainedSockSize: Int = 8192,
    val maxMemInQueuesBytes: Long = 0,
    val maxMemInQueuesLowThresholdBytes: Long = 0,
    val maxConsensusAgeForDiffsSec: Long = 72 * 3600,
    val protocolWarnings: Boolean = false,
    val allowNonRfc953Hostnames: Boolean = false,
    val clientPreferIpv6OrPort: Boolean = false,
    val clientPreferIpv6DirPort: Boolean = false,
    val reducedCircuitPadding: Boolean = false,
    val reducedConnectionPadding: Boolean = false,
    val updateBridgesFromAuthority: Boolean = false,
    val virtualAddrNetworkIpv6: String = "FE80::/10",
    val accountingRule: String = "max",
    val dirAuthorityFallbackRate: Double = 0.1,
    val dirPortFrontPage: Path? = null,
    val extOrPortCookieAuthFile: Path? = null,
    val controlPortWriteToFile: Path? = null,
    val controlPortFileGroupReadable: Boolean = false,
    val cookieAuthFileGroupReadable: Boolean = false,
    val dataDirectoryGroupReadable: Boolean = false,
    val cacheDirectoryGroupReadable: Boolean = false,
    val keyDirectoryGroupReadable: Boolean = false,
    val extOrPortCookieAuthFileGroupReadable: Boolean = false,
    val controlSocketsGroupWritable: Boolean = false,
    val addressDisableIPv6: Boolean = false,
    val logTimeGranularityMs: Int = 1,
    val connLimitHighThresh: Int = 0,
    val connLimitLowThresh: Int = 0,
    val metricsPortPolicy: String? = null,
    val socksPolicyLines: List<String> = emptyList(),
    val sessionGroup: Int = -1,
    val owningControllerFd: Long? = null,
    val syslogIdentityTag: String? = null,
    val androidIdentityTag: String? = null,
    val logFile: Path? = null,
    val logMessageDomains: Boolean = false,
    val keepBindCapabilities: Boolean = false,
    val disableAllSwap: Boolean = false,
    val hardwareAccel: Boolean = false,
    val accelName: String? = null,
    val accelDir: Path? = null,
    val countPrivateBandwidth: Boolean = false,
    val fetchV2Networkstatus: Boolean = false,
    val bridgeRecordUsageByCountry: Boolean = false,
    val natdPort: ListenSpec? = null,
    val transProxyType: String = "default",
    val dnsListenAddress: String? = null,
    val serverTransportOptions: List<String> = emptyList(),
    /** DoS*DefenseType integers (1=none/refuse lite). */
    val dosCircuitCreationDefenseType: Int = 1,
    val dosConnectionDefenseType: Int = 1,
    val dosStreamCreationDefenseType: Int = 1,
    val dosCircuitCreationDefenseTimePeriodSec: Long = 60 * 60,
) {
    fun effectiveNumCpus(): Int =
        if (numCpus > 0) numCpus else Runtime.getRuntime().availableProcessors().coerceAtLeast(1)
}

/**
 * ServerDNS* options (C Tor exit DNS resolver prefs).
 */
data class ServerDnsOptions(
    val resolvConfFile: Path? = null,
    val allowBrokenConfig: Boolean = false,
    val searchDomains: Boolean = false,
    val detectHijacking: Boolean = true,
    val testAddresses: List<String> = listOf("www.google.com", "www.mit.edu", "www.yahoo.com", "www.slashdot.org"),
    val allowNonRfc953Hostnames: Boolean = false,
    val randomizeCase: Boolean = true,
)

/**
 * PidFile write/delete (C Tor `options_act` pidfile lite).
 */
object PidFile {
    fun write(path: Path?) {
        if (path == null) return
        java.nio.file.Files.createDirectories(path.parent ?: return)
        path.writeTextCompat(ProcessHandle.current().pid().toString() + "\n")
    }

    fun delete(path: Path?) {
        if (path == null) return
        runCatching { java.nio.file.Files.deleteIfExists(path) }
    }
}
