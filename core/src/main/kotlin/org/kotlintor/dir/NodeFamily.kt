package org.kotlintor.dir

import java.util.concurrent.ConcurrentHashMap

/**
 * Encoded node families (C Tor `nodefamily.c`).
 *
 * Canonical sets of identity fingerprints (and optional nicknames) used for
 * path-spec family exclusion. Interned by sorted fingerprint key.
 *
 * Inventory: `L1:feature/nodelist/nodefamily.c`
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

        /** C Tor `nodefamily_canonicalize`. */
        fun nodefamilyCanonicalize(s: String): String? =
            parse(s)?.members?.map { it.uppercase() }?.sorted()?.joinToString(",")

        /** C Tor `nodefamily_contains_nickname`. */
        fun nodefamilyContainsNickname(nf: NodeFamily, nickname: String): Boolean =
            nf.members.any { it.equals(nickname, ignoreCase = true) }

        /** C Tor `nodefamily_contains_node` — nickname or RSA id. */
        fun nodefamilyContainsNode(
            nf: NodeFamily,
            fingerprintHex: String,
            nickname: String? = null,
        ): Boolean {
            if (nf.containsFingerprint(fingerprintHex)) return true
            if (nickname != null && nodefamilyContainsNickname(nf, nickname)) return true
            return false
        }

        /** C Tor `nodefamily_contains_rsa_id`. */
        fun nodefamilyContainsRsaId(nf: NodeFamily, fingerprintHex: String): Boolean =
            nf.containsFingerprint(fingerprintHex)

        /** C Tor `nodefamily_add_nodes_to_smartlist` — resolve via [NodeList] process list. */
        fun nodefamilyAddNodesToSmartlist(nf: NodeFamily): List<RouterStatus> {
            val out = ArrayList<RouterStatus>()
            for (m in nf.members) {
                val rs = when {
                    Nickname.isLegalHexdigest(m) || m.startsWith('$') ->
                        Nickname.parseHexdigest(m)?.let { NodeList.nodeGetByHexId(it) }
                    else -> NodeList.processList().byNickname(m)
                }
                if (rs != null) out += rs
            }
            return out
        }
    }
}
