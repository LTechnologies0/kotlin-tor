package org.kotlintor.dir

import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * Bridge authority status dump (C Tor `bridgeauth.c`).

 * Inventory: `L1:feature/dirauth/bridgeauth.c`
 */
object BridgeAuth {
    data class BridgeStatus(
        val identityHex: String,
        val nickname: String,
        val ip: String,
        val orPort: Int,
        val flags: Set<String>,
        val bandwidthKb: Int = 0,
    )

    fun formatNetworkstatusBridges(
        bridges: List<BridgeStatus>,
        publishedEpochSec: Long = System.currentTimeMillis() / 1000,
        fingerprintHex: String? = null,
        flagThresholds: String = "stable-uptime=0 stable-mtbf=0 fast-speed=0 guard-wfu=0 guard-tk=0 guard-bw-inc-exits=0 guard-bw-exc-exits=0 enough-mtbf=0 ignoring-advertised-bws=0",
    ): String {
        val published = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneOffset.UTC)
            .format(Instant.ofEpochSecond(publishedEpochSec))
        return buildString {
            appendLine("published $published")
            appendLine("flag-thresholds $flagThresholds")
            if (fingerprintHex != null) appendLine("fingerprint $fingerprintHex")
            for (b in bridges) {
                appendLine(
                    "r ${b.nickname} ${b.identityHex} AA $published ${b.ip} ${b.orPort} 0",
                )
                appendLine("s ${b.flags.joinToString(" ")}")
                if (b.bandwidthKb > 0) appendLine("w Bandwidth=${b.bandwidthKb}")
            }
        }
    }

    fun dumpToFile(dataDir: Path, body: String): Path {
        val out = dataDir.resolve("networkstatus-bridges")
        Files.createDirectories(dataDir)
        Files.writeString(out, body)
        return out
    }

    /**
     * C Tor `bridgeauth_dump_bridge_status_to_file` — format + write under [dataDir].
     */
    fun bridgeauthDumpBridgeStatusToFile(
        dataDir: Path,
        bridges: List<BridgeStatus>,
        nowEpochSec: Long = System.currentTimeMillis() / 1000,
        fingerprintHex: String? = null,
    ): Path {
        val body = formatNetworkstatusBridges(bridges, publishedEpochSec = nowEpochSec, fingerprintHex = fingerprintHex)
        return dumpToFile(dataDir, body)
    }
}

