package org.kotlintor.dir

/**
 * Bandwidth-authority file parse/cache (C Tor `bwauth.c`).
 *
 * Format: optional headers, `=====\n` terminator, then lines with
 * `node_id=$HEX` and `bw=KB` (plus ignored key=value tokens).
 */
object BwAuthFile {
    const val HEADERS_TERMINATOR: String = "====="
    /** C Tor `MAX_MEASUREMENT_AGE` — 3 days. */
    const val MAX_MEASUREMENT_AGE_SEC: Long = 3L * 24 * 60 * 60
    const val MAX_HEADER_COUNT_IN_VOTE: Int = 50

    data class MeasuredLine(val nodeIdHex: String, val bwKb: Long)

    data class Parsed(
        val headers: Map<String, String>,
        val lines: List<MeasuredLine>,
    )

    fun parse(text: String): Parsed {
        val headers = linkedMapOf<String, String>()
        val lines = ArrayList<MeasuredLine>()
        var afterHeaders = false
        for (raw in text.lineSequence()) {
            val line = raw.trimEnd()
            if (!afterHeaders) {
                if (line == HEADERS_TERMINATOR) {
                    afterHeaders = true
                    continue
                }
                if (line.isEmpty() || line.startsWith("#")) continue
                val eq = line.indexOf('=')
                if (eq > 0 && headers.size < MAX_HEADER_COUNT_IN_VOTE) {
                    headers[line.substring(0, eq)] = line.substring(eq + 1)
                }
                continue
            }
            parseRelayLine(line)?.let { lines += it }
        }
        // Files without terminator: treat all non-empty key lines as measurements.
        if (!afterHeaders && lines.isEmpty()) {
            for (raw in text.lineSequence()) {
                parseRelayLine(raw.trimEnd())?.let { lines += it }
            }
        }
        return Parsed(headers, lines)
    }

    fun parseRelayLine(line: String): MeasuredLine? {
        if (line.isEmpty() || line.startsWith("#")) return null
        var nodeId: String? = null
        var bw: Long? = null
        for (tok in line.split(Regex("\\s+"))) {
            when {
                tok.startsWith("node_id=$") -> nodeId = tok.removePrefix("node_id=$").uppercase()
                tok.startsWith("node_id=") -> nodeId = tok.removePrefix("node_id=").removePrefix("$").uppercase()
                tok.startsWith("bw=") -> bw = tok.removePrefix("bw=").toLongOrNull()
            }
        }
        if (nodeId.isNullOrEmpty() || bw == null) return null
        return MeasuredLine(nodeId, bw.coerceAtLeast(0))
    }
}

/**
 * In-memory measured-bandwidth cache (C Tor `dirserv_cache_measured_bw`).
 */
class MeasuredBwCache {
    data class Entry(val bwKb: Long, val asOfEpochSec: Long)

    private val byId = LinkedHashMap<String, Entry>()

    fun put(nodeIdHex: String, bwKb: Long, asOfEpochSec: Long = System.currentTimeMillis() / 1000) {
        byId[nodeIdHex.uppercase()] = Entry(bwKb, asOfEpochSec)
    }

    fun load(file: BwAuthFile.Parsed, asOfEpochSec: Long = System.currentTimeMillis() / 1000) {
        for (line in file.lines) put(line.nodeIdHex, line.bwKb, asOfEpochSec)
    }

    fun get(nodeIdHex: String, nowEpochSec: Long = System.currentTimeMillis() / 1000): Long? {
        val e = byId[nodeIdHex.uppercase()] ?: return null
        if (nowEpochSec - e.asOfEpochSec > BwAuthFile.MAX_MEASUREMENT_AGE_SEC) return null
        return e.bwKb
    }

    fun expire(nowEpochSec: Long = System.currentTimeMillis() / 1000) {
        val it = byId.entries.iterator()
        while (it.hasNext()) {
            val e = it.next()
            if (nowEpochSec - e.value.asOfEpochSec > BwAuthFile.MAX_MEASUREMENT_AGE_SEC) it.remove()
        }
    }

    val size: Int get() = byId.size
}

/**
 * Lite vote collator (C Tor `dircollate.c`): group router `w` lines by identity
 * token and emit median Bandwidth= for a consensus body fragment.
 */
object DirCollator {
    data class CollatedRouter(
        val identity: String,
        val nickname: String?,
        val bandwidthKb: Long,
        val voteCount: Int,
    )

    /**
     * Include routers present in at least `ceil(nAuthorities/2)` votes when
     * [nAuthorities] > 0; otherwise require appearance in ≥1 vote.
     */
    fun collate(
        votes: List<BandwidthVote.VoteDocument>,
        nAuthorities: Int = votes.size,
    ): List<CollatedRouter> {
        data class Acc(var nick: String?, val bws: MutableList<Long>)
        val byId = LinkedHashMap<String, Acc>()
        for (v in votes) {
            for (r in v.routers) {
                val id = r.identityHex ?: continue
                val acc = byId.getOrPut(id) { Acc(r.nickname, mutableListOf()) }
                if (acc.nick == null) acc.nick = r.nickname
                acc.bws += r.measured ?: r.bandwidth
            }
        }
        val threshold = if (nAuthorities > 0) (nAuthorities + 1) / 2 else 1
        return byId.mapNotNull { (id, acc) ->
            if (acc.bws.size < threshold) return@mapNotNull null
            val sorted = acc.bws.sorted()
            val median = sorted[sorted.size / 2]
            CollatedRouter(id, acc.nick, median, acc.bws.size)
        }.sortedBy { it.identity }
    }

    fun formatConsensusBody(
        routers: List<CollatedRouter>,
        sharedRandom: SharedRandom.Srv? = null,
        previousSharedRandom: SharedRandom.Srv? = null,
    ): String = buildString {
        appendLine("network-status-version 3")
        appendLine("vote-status consensus")
        previousSharedRandom?.let { append(it.toNsLine("shared-rand-previous-value")) }
        sharedRandom?.let { append(it.toNsLine("shared-rand-current-value")) }
        for (r in routers) {
            appendLine("r ${r.nickname ?: "Unnamed"} ${r.identity} AA 2020-01-01 00:00:00 127.0.0.1 9001 0")
            appendLine(BandwidthVote.formatWLine(r.bandwidthKb, measured = r.bandwidthKb))
            appendLine("s Fast Running Stable Valid")
        }
        appendLine("directory-footer")
    }
}
