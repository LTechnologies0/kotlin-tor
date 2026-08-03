package org.kotlintor.dir

/**
 * Nickname / hexdigest validators (C Tor `nickname.c`).
 */
object Nickname {
    const val MAX_NICKNAME_LEN: Int = 19
    const val HEX_DIGEST_LEN: Int = 40
    private const val LEGAL =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    private val LEGAL_SET = LEGAL.toSet()
    private val HEX_SET = "0123456789abcdefABCDEF".toSet()

    fun isLegalNickname(s: String): Boolean {
        if (s.isEmpty() || s.length > MAX_NICKNAME_LEN) return false
        return s.all { it in LEGAL_SET }
    }

    fun isLegalHexdigest(s: String): Boolean {
        var t = s
        if (t.startsWith('$')) t = t.substring(1)
        if (t.length < HEX_DIGEST_LEN) return false
        if (t.length > HEX_DIGEST_LEN) {
            val sep = t[HEX_DIGEST_LEN]
            if (sep == '=' || sep == '~') {
                if (!isLegalNickname(t.substring(HEX_DIGEST_LEN + 1))) return false
            } else {
                return false
            }
        }
        return t.take(HEX_DIGEST_LEN).all { it in HEX_SET }
    }

    fun isLegalNicknameOrHexdigest(s: String): Boolean =
        if (s.startsWith('$')) isLegalHexdigest(s) else isLegalNickname(s)

    /** Strip `$` and optional `=nick` / `~nick` suffix → 40-char hex uppercase. */
    fun parseHexdigest(s: String): String? {
        if (!isLegalHexdigest(s)) return null
        var t = if (s.startsWith('$')) s.substring(1) else s
        if (t.length > HEX_DIGEST_LEN) t = t.take(HEX_DIGEST_LEN)
        return t.uppercase()
    }
}

/**
 * Human-readable node descriptions (C Tor `describe.c` lite).
 */
object Describe {
    fun node(
        nickname: String?,
        identityHex: String?,
        ipv4: String? = null,
        orPort: Int? = null,
        ed25519Hex: String? = null,
    ): String {
        val id = identityHex?.uppercase()?.take(40)
        val nick = nickname?.takeIf { it.isNotEmpty() } ?: "Unnamed"
        val addr = when {
            ipv4 != null && orPort != null -> "$ipv4:$orPort"
            ipv4 != null -> ipv4
            else -> null
        }
        return buildString {
            append('$')
            append(id ?: "????????????????????????????????????????")
            append('~')
            append(nick)
            if (addr != null) {
                append(" at ")
                append(addr)
            }
            if (!ed25519Hex.isNullOrBlank()) {
                append(" ed=")
                append(ed25519Hex.lowercase().take(16))
                append("…")
            }
        }
    }

    fun routerStatus(rs: RouterStatus): String =
        node(rs.nickname, rs.fingerprintHex, rs.ip, rs.orPort, rs.ed25519Identity?.let {
            it.joinToString("") { b -> "%02x".format(b) }
        })
}

/**
 * Node selection helpers (C Tor `node_select.c` / weight by bandwidth lite).
 */
object NodeSelect {
    fun byBandwidth(relays: List<RouterStatus>, preferFlags: Set<String> = emptySet()): RouterStatus? {
        val pool = relays.filter { it.isRunning && it.isFast }
            .filter { r -> preferFlags.isEmpty() || preferFlags.any { it in r.flags } }
        if (pool.isEmpty()) return null
        val weights = pool.map { (it.bandwidth.coerceAtLeast(1)).toDouble() }
        val total = weights.sum()
        var r = org.kotlintor.util.SecureRandomSource.nextDouble() * total
        for (i in pool.indices) {
            r -= weights[i]
            if (r <= 0) return pool[i]
        }
        return pool.last()
    }

    fun pickDistinct(
        relays: List<RouterStatus>,
        n: Int,
        exclude: Set<String> = emptySet(),
        preferFlags: Set<String> = emptySet(),
    ): List<RouterStatus> {
        val out = ArrayList<RouterStatus>(n)
        val used = exclude.map { it.uppercase() }.toMutableSet()
        repeat(n) {
            val cand = relays.filter { it.fingerprintHex !in used }
            val pick = byBandwidth(cand, preferFlags) ?: return out
            out += pick
            used += pick.fingerprintHex
        }
        return out
    }
}
