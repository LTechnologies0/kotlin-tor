package org.kotlintor.dir

import java.util.concurrent.ConcurrentHashMap

/**
 * Encoded node families (C Tor `nodefamily.c` lite).
 *
 * Canonical sets of identity fingerprints (and optional nicknames) used for
 * path-spec family exclusion. Interned by sorted fingerprint key.
 */
data class NodeFamily(
    val members: Set<String>,
) {
    init {
        require(members.isNotEmpty())
    }

    /** Uppercase fingerprints only (nicknames dropped for matching). */
    val fingerprints: Set<String> =
        members.mapNotNull { token ->
            when {
                token.startsWith('$') -> Nickname.parseHexdigest(token)
                Nickname.isLegalHexdigest(token) -> Nickname.parseHexdigest(token)
                else -> null
            }
        }.toSet()

    fun containsFingerprint(fpHex: String): Boolean =
        fpHex.uppercase() in fingerprints || fpHex.uppercase() in members.map { it.uppercase() }

    fun intersects(other: NodeFamily): Boolean =
        fingerprints.any { it in other.fingerprints }

    companion object {
        /**
         * Parse a space/comma-separated family declaration.
         * @param selfFp optional declaring router's RSA identity (always included).
         */
        fun parse(s: String, selfFp: String? = null): NodeFamily? {
            val tokens = s.split(Regex("[,\\s]+")).map { it.trim() }.filter { it.isNotEmpty() }
            if (tokens.isEmpty() && selfFp == null) return null
            val members = linkedSetOf<String>()
            for (t in tokens) {
                when {
                    t.startsWith('$') || Nickname.isLegalHexdigest(t) ->
                        Nickname.parseHexdigest(t)?.let { members += it }
                    Nickname.isLegalNickname(t) -> members += t
                    else -> { /* omit malformed */ }
                }
            }
            selfFp?.let { members += it.replace(" ", "").uppercase() }
            if (members.isEmpty()) return null
            return intern(NodeFamily(members))
        }

        private val cache = ConcurrentHashMap<String, NodeFamily>()

        fun intern(nf: NodeFamily): NodeFamily {
            val key = nf.members.map { it.uppercase() }.sorted().joinToString(",")
            return cache.getOrPut(key) { nf.copy(members = nf.members.map { it.uppercase() }.toSet()) }
        }

        fun clearCache() = cache.clear()
    }
}

/**
 * Router list index (C Tor `routerlist.c` lite).
 *
 * Indexes [RouterStatus] by fingerprint and nickname for O(1) lookup.
 */
class RouterList {
    private val byFp = ConcurrentHashMap<String, RouterStatus>()
    private val byNick = ConcurrentHashMap<String, RouterStatus>()

    fun clear() {
        byFp.clear()
        byNick.clear()
    }

    fun add(rs: RouterStatus) {
        byFp[rs.fingerprintHex] = rs
        byNick[rs.nickname.lowercase()] = rs
    }

    fun addAll(relays: Collection<RouterStatus>) {
        relays.forEach { add(it) }
    }

    fun byFingerprint(fpHex: String): RouterStatus? =
        byFp[fpHex.replace(" ", "").uppercase()]

    fun byNickname(nick: String): RouterStatus? = byNick[nick.lowercase()]

    /** Resolve nickname, `$hex`, or hex digest. */
    fun lookup(token: String): RouterStatus? {
        val t = token.trim()
        if (t.startsWith('$') || Nickname.isLegalHexdigest(t)) {
            return Nickname.parseHexdigest(t)?.let { byFingerprint(it) }
        }
        return byNickname(t)
    }

    fun size(): Int = byFp.size

    fun all(): Collection<RouterStatus> = byFp.values

    fun running(): List<RouterStatus> = byFp.values.filter { it.isRunning }

    fun exits(): List<RouterStatus> = byFp.values.filter { it.isRunning && it.isExit }

    fun guards(): List<RouterStatus> = byFp.values.filter { it.isRunning && it.isGuard }

    /** Exclude fingerprints / nicknames (ExcludeNodes lite). */
    fun filterExclude(exclude: Collection<String>): List<RouterStatus> {
        if (exclude.isEmpty()) return all().toList()
        val ban = exclude.map { it.trim().removePrefix("$").uppercase() }.filter { it.isNotEmpty() }.toSet()
        return byFp.values.filter { rs ->
            rs.fingerprintHex.uppercase() !in ban && rs.nickname.uppercase() !in ban
        }
    }

    fun pickWeighted(
        preferFlags: Set<String> = emptySet(),
        exclude: Set<String> = emptySet(),
    ): RouterStatus? =
        NodeSelect.byBandwidth(filterExclude(exclude), preferFlags)

    fun pickDistinct(
        n: Int,
        exclude: Set<String> = emptySet(),
        preferFlags: Set<String> = emptySet(),
    ): List<RouterStatus> =
        NodeSelect.pickDistinct(all().toList(), n, exclude, preferFlags)

    fun applyFamiliesFromDescriptors(familyLines: Map<String, String>) {
        for ((fp, line) in familyLines) {
            NodeFamily.parse(line, selfFp = fp)
        }
    }
}
