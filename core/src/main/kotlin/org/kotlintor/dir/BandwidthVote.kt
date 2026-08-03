package org.kotlintor.dir

/**
 * Bandwidth vote / measurement artifacts (dir-spec).
 *
 * Full directory authority consensus voting remains a multi-process role;
 * this module implements the **document formats and a client-side bandwidth
 * probe** so relays/clients can produce and consume `w Bandwidth=` lines
 * without claiming a complete dirauth.
 */
object BandwidthVote {
    data class VoteHeader(
        val networkStatusVersion: Int,
        val voteStatus: String,
        val published: String?,
        val validAfter: String?,
        val freshUntil: String?,
        val validUntil: String?,
        val votingDelay: Pair<Int, Int>?,
        val knownFlags: List<String>,
        val params: Map<String, String>,
    )

    data class RouterBandwidth(
        val nickname: String?,
        val identityHex: String?,
        /** Measured or observed bandwidth (kilobytes/s as in dir-spec `w Bandwidth=`). */
        val bandwidth: Long,
        val measured: Long? = null,
        val unmeasured: Boolean = false,
        val ip: String? = null,
        val orPort: Int? = null,
        val ed25519IdentityHex: String? = null,
    )

    data class VoteDocument(
        val header: VoteHeader,
        val routers: List<RouterBandwidth>,
        val raw: String,
    )

    /**
     * Parse a subset of a vote / consensus network-status document focusing on
     * preamble + `r` / `w` bandwidth lines.
     */
    fun parse(text: String): VoteDocument {
        var networkStatusVersion = 3
        var voteStatus = "unknown"
        var published: String? = null
        var validAfter: String? = null
        var freshUntil: String? = null
        var validUntil: String? = null
        var votingDelay: Pair<Int, Int>? = null
        var knownFlags = emptyList<String>()
        val params = linkedMapOf<String, String>()
        val routers = ArrayList<RouterBandwidth>()
        var curNick: String? = null
        var curId: String? = null
        var curIp: String? = null
        var curOrPort: Int? = null
        var curEd: String? = null

        for (rawLine in text.lineSequence()) {
            val line = rawLine.trimEnd()
            if (line.isEmpty() || line.startsWith("-----")) continue
            when {
                line.startsWith("network-status-version ") ->
                    networkStatusVersion = line.removePrefix("network-status-version ").trim().toIntOrNull() ?: 3
                line.startsWith("vote-status ") ->
                    voteStatus = line.removePrefix("vote-status ").trim()
                line.startsWith("published ") -> published = line.removePrefix("published ").trim()
                line.startsWith("valid-after ") -> validAfter = line.removePrefix("valid-after ").trim()
                line.startsWith("fresh-until ") -> freshUntil = line.removePrefix("fresh-until ").trim()
                line.startsWith("valid-until ") -> validUntil = line.removePrefix("valid-until ").trim()
                line.startsWith("voting-delay ") -> {
                    val p = line.removePrefix("voting-delay ").trim().split(Regex("\\s+"))
                    if (p.size >= 2) {
                        votingDelay = (p[0].toIntOrNull() ?: 0) to (p[1].toIntOrNull() ?: 0)
                    }
                }
                line.startsWith("known-flags ") ->
                    knownFlags = line.removePrefix("known-flags ").trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
                line.startsWith("params ") -> {
                    line.removePrefix("params ").trim().split(Regex("\\s+")).forEach { tok ->
                        val eq = tok.indexOf('=')
                        if (eq > 0) params[tok.substring(0, eq)] = tok.substring(eq + 1)
                    }
                }
                line.startsWith("r ") -> {
                    val parts = line.removePrefix("r ").trim().split(Regex("\\s+"))
                    curNick = parts.getOrNull(0)
                    // identity is base64 in votes; keep raw token for now
                    curId = parts.getOrNull(1)
                    curIp = parts.getOrNull(5)
                    curOrPort = parts.getOrNull(6)?.toIntOrNull()
                    curEd = null
                }
                line.startsWith("id ed25519 ") -> {
                    curEd = line.removePrefix("id ed25519 ").trim().lowercase()
                }
                line.startsWith("w ") -> {
                    var bw = 0L
                    var measured: Long? = null
                    var unmeasured = false
                    line.removePrefix("w ").trim().split(Regex("\\s+")).forEach { tok ->
                        when {
                            tok.startsWith("Bandwidth=") -> bw = tok.removePrefix("Bandwidth=").toLongOrNull() ?: 0
                            tok.startsWith("Measured=") -> measured = tok.removePrefix("Measured=").toLongOrNull()
                            tok == "Unmeasured=1" -> unmeasured = true
                        }
                    }
                    routers += RouterBandwidth(
                        nickname = curNick,
                        identityHex = curId,
                        bandwidth = bw,
                        measured = measured,
                        unmeasured = unmeasured,
                        ip = curIp,
                        orPort = curOrPort,
                        ed25519IdentityHex = curEd,
                    )
                }
            }
        }
        val header = VoteHeader(
            networkStatusVersion, voteStatus, published, validAfter, freshUntil, validUntil,
            votingDelay, knownFlags, params,
        )
        return VoteDocument(header, routers, text)
    }

    /** Format a single dir-spec `w` line. */
    fun formatWLine(bandwidthKb: Long, measured: Long? = null, unmeasured: Boolean = false): String {
        val sb = StringBuilder("w Bandwidth=").append(bandwidthKb.coerceAtLeast(0))
        if (measured != null) sb.append(" Measured=").append(measured.coerceAtLeast(0))
        if (unmeasured) sb.append(" Unmeasured=1")
        return sb.toString()
    }

    /**
     * Emit a minimal vote-status document body (unsigned) carrying one router `w` line.
     * Suitable for tests and bandwidth-authority scaffolding — not a full dirauth vote.
     */
    fun formatMinimalVote(
        nickname: String,
        identityToken: String,
        bandwidthKb: Long,
        published: String = "2020-01-01 00:00:00",
        validAfter: String = published,
        freshUntil: String = published,
        validUntil: String = published,
    ): String = buildString {
        appendLine("network-status-version 3")
        appendLine("vote-status vote")
        appendLine("published $published")
        appendLine("valid-after $validAfter")
        appendLine("fresh-until $freshUntil")
        appendLine("valid-until $validUntil")
        appendLine("voting-delay 300 300")
        appendLine("known-flags Fast Guard Stable Running Valid")
        appendLine("r $nickname $identityToken AA 2020-01-01 00:00:00 127.0.0.1 9001 0")
        appendLine(formatWLine(bandwidthKb))
        appendLine("s Fast Running Stable Valid")
    }
}

/**
 * Client-side bandwidth probe: download [bytes] through a provided reader and
 * estimate kilobytes/s for a `w Bandwidth=` line.
 */
object BandwidthProbe {
    data class Result(val bytes: Long, val elapsedMs: Long, val bandwidthKbPerSec: Long)

    suspend fun measure(read: suspend (ByteArray) -> Int, bytes: Long = 256 * 1024L): Result {
        val buf = ByteArray(16 * 1024)
        var got = 0L
        val t0 = System.nanoTime()
        while (got < bytes) {
            val n = read(buf)
            if (n < 0) break
            if (n == 0) continue
            got += n
        }
        val elapsedMs = ((System.nanoTime() - t0) / 1_000_000L).coerceAtLeast(1)
        val kbPerSec = ((got * 1000L) / elapsedMs) / 1024L
        return Result(got, elapsedMs, kbPerSec.coerceAtLeast(1))
    }
}
