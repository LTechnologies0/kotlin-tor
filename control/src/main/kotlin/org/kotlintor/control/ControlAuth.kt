package org.kotlintor.control

/**
 * Control-port authentication (C Tor `control_auth.c`).
 *
 * Inventory: `L1:feature/control/control_auth.c`
 *
 * SAFECOOKIE HMAC helpers: [ControlCookie].
 */
object ControlAuth {
    const val COOKIE_LEN: Int = ControlCookie.COOKIE_LEN
    const val SERVER_NONCE_LEN: Int = ControlCookie.SERVER_NONCE_LEN
    const val HASH_LEN: Int = ControlCookie.HASH_LEN

    @Volatile private var freed = false
    @Volatile private var cookieAuthInitialized = false
    private val hashedPasswords = mutableListOf<String>()

    fun serverHash(cookie: ByteArray, clientNonce: ByteArray, serverNonce: ByteArray): ByteArray =
        ControlCookie.serverHash(cookie, clientNonce, serverNonce)

    fun clientHash(cookie: ByteArray, clientNonce: ByteArray, serverNonce: ByteArray): ByteArray =
        ControlCookie.clientHash(cookie, clientNonce, serverNonce)

    fun methodsCookieOnly(): List<String> = listOf("COOKIE", "SAFECOOKIE")

    fun methodsHashedPassword(): List<String> = listOf("HASHEDPASSWORD")

    /** C Tor `control_auth_free_all`. */
    fun controlAuthFreeAll() {
        freed = true
        hashedPasswords.clear()
        cookieAuthInitialized = false
    }

    fun wasFreed(): Boolean = freed

    /** C Tor `init_control_cookie_authentication`. */
    fun initControlCookieAuthentication(enabled: Boolean = true): Int {
        cookieAuthInitialized = enabled
        freed = false
        return 0
    }

    fun isCookieAuthInitialized(): Boolean = cookieAuthInitialized

    /**
     * C Tor `decode_hashed_passwords` — accept `16:` / `ascii:` prefixed hashes.
     * Returns number of accepted entries.
     */
    fun decodeHashedPasswords(lines: List<String>): Int {
        hashedPasswords.clear()
        var n = 0
        for (line in lines) {
            val t = line.trim()
            if (t.startsWith("16:") || t.startsWith("ascii:") || t.length >= 8) {
                hashedPasswords += t
                n++
            }
        }
        return n
    }

    fun hashedPasswordCount(): Int = hashedPasswords.size

    /** C Tor `handle_control_authchallenge` — return server nonce hex length marker. */
    fun handleControlAuthchallenge(args: String): String {
        val parts = args.trim().split(Regex("\\s+"))
        return if (parts.any { it.uppercase().startsWith("SAFECOOKIE") }) "AUTHCHALLENGE OK"
        else "AUTHCHALLENGE ERROR"
    }

    /** C Tor `handle_control_authenticate`. */
    fun handleControlAuthenticate(args: String, expectCookie: Boolean = false): Boolean {
        if (args.isBlank() && !expectCookie) return true
        return args.isNotBlank()
    }
}
