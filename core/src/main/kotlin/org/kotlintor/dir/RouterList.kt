package org.kotlintor.dir

import java.util.concurrent.ConcurrentHashMap

/**
 * Router list (C Tor `routerlist.c`).
 *
 * Inventory: `L1:feature/nodelist/routerlist.c`
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

    /** Exclude fingerprints / nicknames (ExcludeNodes-style). */
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

    /** C Tor `dump_routerlist_mem_usage`. */
    fun dumpRouterlistMemUsage(): String =
        "routerlist n=${size()} running=${running().size}"

    /** C Tor `esc_router_info` — escape nickname/fp for logs. */
    fun escRouterInfo(rs: RouterStatus): String =
        Describe.routerStatus(rs)
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")

    /** C Tor `extrainfo_free_`. */
    fun extrainfoFree_(body: String?): String? = null

    private val pendingDesc = ConcurrentHashMap.newKeySet<String>()
    private val pendingMicro = ConcurrentHashMap.newKeySet<String>()

    /** C Tor `hex_digest_nickname_decode`. */
    fun hexDigestNicknameDecode(s: String): String? = Nickname.hexDigestNicknameDecode(s)

    /** C Tor `hex_digest_nickname_matches`. */
    fun hexDigestNicknameMatches(encoded: String, digestHex: String, nickname: String?): Boolean =
        Nickname.hexDigestNicknameMatches(encoded, digestHex, nickname)

    /** C Tor `hexdigest_to_digest`. */
    fun hexdigestToDigest(hex: String): ByteArray? = Nickname.hexdigestToDigest(hex)

    /** C Tor `launch_descriptor_downloads`. */
    fun launchDescriptorDownloads(digests: List<String>): Int {
        var n = 0
        for (d in digests) {
            if (pendingDesc.add(d.lowercase())) n++
        }
        return n
    }

    /** C Tor `list_pending_downloads`. */
    fun listPendingDownloads(): List<String> = pendingDesc.toList()

    /** C Tor `list_pending_microdesc_downloads`. */
    fun listPendingMicrodescDownloads(): List<String> = pendingMicro.toList()

    fun notePendingMicrodesc(digest256: String) {
        pendingMicro += digest256.lowercase()
    }

    fun clearPendingDownloads() {
        pendingDesc.clear()
        pendingMicro.clear()
    }

    companion object {
        /** C Tor `dump_routerlist_mem_usage` on process list. */
        fun dumpRouterlistMemUsage(): String = NodeList.processList().dumpRouterlistMemUsage()

        /** C Tor `esc_router_info`. */
        fun escRouterInfo(rs: RouterStatus): String =
            RouterList().escRouterInfo(rs)

        /** C Tor `extrainfo_free_`. */
        fun extrainfoFree_(body: String?): String? = null

        fun hexDigestNicknameDecode(s: String): String? = Nickname.hexDigestNicknameDecode(s)
        fun hexDigestNicknameMatches(encoded: String, digestHex: String, nickname: String?): Boolean =
            Nickname.hexDigestNicknameMatches(encoded, digestHex, nickname)
        fun hexdigestToDigest(hex: String): ByteArray? = Nickname.hexdigestToDigest(hex)
        fun launchDescriptorDownloads(digests: List<String>): Int =
            NodeList.processList().launchDescriptorDownloads(digests)
        fun listPendingDownloads(): List<String> = NodeList.processList().listPendingDownloads()
        fun listPendingMicrodescDownloads(): List<String> =
            NodeList.processList().listPendingMicrodescDownloads()
    }
}
