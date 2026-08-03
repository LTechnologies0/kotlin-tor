package org.kotlintor.dir

import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.concurrent.ConcurrentHashMap

/**
 * RecommendedPackages line validation (C Tor `recommend_pkg.c`).
 *
 * Grammar: `PACKAGENAME VERSION URL DIGESTTYPE=DIGESTVAL…`
 */
object RecommendPkg {
    data class Package(
        val name: String,
        val version: String,
        val url: String,
        val digests: Map<String, String>,
    )

    fun validate(line: String): Boolean = parse(line) != null

    fun parse(line: String): Package? {
        val parts = line.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
        if (parts.size < 4) return null
        val digests = LinkedHashMap<String, String>()
        for (i in 3 until parts.size) {
            val eq = parts[i].indexOf('=')
            if (eq <= 0 || eq == parts[i].lastIndex) return null
            if (parts[i].indexOf('=', eq + 1) >= 0) return null
            digests[parts[i].substring(0, eq)] = parts[i].substring(eq + 1)
        }
        if (digests.isEmpty()) return null
        return Package(parts[0], parts[1], parts[2], digests)
    }
}

/**
 * Bridge authority status dump (C Tor `bridgeauth.c`).
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
}

/**
 * Client-side shared random values from consensus (C Tor `shared_random_client.c`).
 */
object SharedRandomClient {
    const val N_ROUNDS: Int = 12
    const val N_PHASES: Int = 2

    data class ParsedSrv(
        val numReveals: Int,
        val valueBase64: String,
        val value: ByteArray,
    )

    /** Parse `shared-rand-current-value N BASE64` / previous from consensus text. */
    fun parseFromConsensus(text: String): Pair<ParsedSrv?, ParsedSrv?> {
        var current: ParsedSrv? = null
        var previous: ParsedSrv? = null
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            when {
                line.startsWith("shared-rand-current-value ") ->
                    current = parseSrvLine(line.removePrefix("shared-rand-current-value ").trim())
                line.startsWith("shared-rand-previous-value ") ->
                    previous = parseSrvLine(line.removePrefix("shared-rand-previous-value ").trim())
            }
        }
        return current to previous
    }

    fun parseSrvLine(args: String): ParsedSrv? {
        val p = args.split(Regex("\\s+"))
        if (p.size < 2) return null
        val n = p[0].toIntOrNull() ?: return null
        val b64 = p[1]
        val value = try {
            java.util.Base64.getDecoder().decode(b64)
        } catch (_: Exception) {
            return null
        }
        if (value.size != 32) return null
        return ParsedSrv(n, b64, value)
    }

    fun getCurrent(nsText: String): ParsedSrv? = parseFromConsensus(nsText).first
    fun getPrevious(nsText: String): ParsedSrv? = parseFromConsensus(nsText).second

    fun forControl(srv: ParsedSrv?): String =
        if (srv == null) "" else "${srv.numReveals} ${srv.valueBase64}"

    /** Voting interval helper (seconds); default 1h when unknown. */
    fun votingIntervalSec(params: Map<String, String> = emptyMap()): Int =
        params["AuthDirVoteInterval"]?.toIntOrNull()
            ?: params["V3AuthVotingInterval"]?.toIntOrNull()
            ?: 3600

    fun phaseDurationSec(voteIntervalSec: Int = 3600): Int =
        voteIntervalSec * N_ROUNDS

    fun protocolRunDurationSec(voteIntervalSec: Int = 3600): Int =
        phaseDurationSec(voteIntervalSec) * N_PHASES

    fun startOfCurrentProtocolRun(nowEpochSec: Long, voteIntervalSec: Int = 3600): Long {
        val run = protocolRunDurationSec(voteIntervalSec).toLong()
        return (nowEpochSec / run) * run
    }

    fun startOfPreviousProtocolRun(nowEpochSec: Long, voteIntervalSec: Int = 3600): Long =
        startOfCurrentProtocolRun(nowEpochSec, voteIntervalSec) -
            protocolRunDurationSec(voteIntervalSec)
}

/**
 * Consensus-diff manager (C Tor `consdiffmgr.c` lite) — store diffs by from→to hash,
 * optionally persist under [storeDir].
 */
class ConsDiffMgr(
    private val cache: ConsCache = ConsCache(),
    private val storeDir: java.nio.file.Path? = null,
) {
    private val diffs = ConcurrentHashMap<String, String>() // "oldHex:newHex" → diff body

    init {
        storeDir?.let { loadFromDisk(it) }
    }

    fun rememberConsensus(body: String): ConsCache.Entry = cache.put(body)

    fun storeDiff(oldBody: String, newBody: String): String {
        val diff = ConsDiff.generate(oldBody, newBody)
        val oldH = ConsDiff.sha3Hex(oldBody)
        val newH = ConsDiff.sha3Hex(newBody)
        val key = "$oldH:$newH"
        diffs[key] = diff
        cache.put(newBody)
        storeDir?.let { dir ->
            runCatching {
                java.nio.file.Files.createDirectories(dir)
                java.nio.file.Files.writeString(dir.resolve("$oldH-$newH.diff"), diff)
            }
        }
        return diff
    }

    fun findDiff(oldSha3Hex: String, newSha3Hex: String): String? =
        diffs["${oldSha3Hex.lowercase()}:${newSha3Hex.lowercase()}"]

    fun applyCached(oldBody: String, newSha3Hex: String): String? {
        val oldH = ConsDiff.sha3Hex(oldBody)
        val diff = findDiff(oldH, newSha3Hex) ?: return null
        return ConsDiff.apply(oldBody, diff)
    }

    fun size(): Int = diffs.size

    fun loadFromDisk(dir: java.nio.file.Path) {
        if (!java.nio.file.Files.isDirectory(dir)) return
        java.nio.file.Files.list(dir).use { stream ->
            stream.filter { it.fileName.toString().endsWith(".diff") }.forEach { path ->
                val name = path.fileName.toString().removeSuffix(".diff")
                val parts = name.split('-', limit = 2)
                if (parts.size == 2 && parts[0].length == 64 && parts[1].length == 64) {
                    val body = runCatching { java.nio.file.Files.readString(path) }.getOrNull() ?: return@forEach
                    diffs["${parts[0]}:${parts[1]}"] = body
                }
            }
        }
    }
}
