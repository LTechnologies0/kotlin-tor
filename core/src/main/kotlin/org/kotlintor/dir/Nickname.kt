package org.kotlintor.dir

/**
 * Nickname / hexdigest validators (C Tor `nickname.c`).
 *
 * Inventory: `L1:feature/nodelist/nickname.c`
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

    /** C Tor `is_legal_nickname`. */
    fun isLegalNicknameAlias(s: String): Boolean = isLegalNickname(s)

    /** C Tor `is_legal_hexdigest`. */
    fun isLegalHexdigestAlias(s: String): Boolean = isLegalHexdigest(s)

    /** C Tor `is_legal_nickname_or_hexdigest`. */
    fun isLegalNicknameOrHexdigestAlias(s: String): Boolean = isLegalNicknameOrHexdigest(s)

    /** C Tor `hex_digest_nickname_decode` — returns digest hex or null. */
    fun hexDigestNicknameDecode(s: String): String? = parseHexdigest(s)

    /** C Tor `hex_digest_nickname_matches`. `=` qualifier never matches. */
    fun hexDigestNicknameMatches(encoded: String, digestHex: String, nickname: String?): Boolean {
        val d = parseHexdigest(encoded) ?: return false
        if (!d.equals(digestHex.replace(" ", ""), ignoreCase = true)) return false
        var t = if (encoded.startsWith('$')) encoded.substring(1) else encoded
        if (t.length <= HEX_DIGEST_LEN) return true
        val sep = t[HEX_DIGEST_LEN]
        if (sep == '=') return false
        if (sep != '~') return false
        if (nickname == null) return false
        val nickPart = t.substring(HEX_DIGEST_LEN + 1)
        return nickPart.equals(nickname, ignoreCase = true)
    }

    /** C Tor `hexdigest_to_digest` — 40 hex → 20 bytes. */
    fun hexdigestToDigest(hex: String): ByteArray? {
        val h = parseHexdigest(hex) ?: return null
        return ByteArray(20) { i ->
            h.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}
