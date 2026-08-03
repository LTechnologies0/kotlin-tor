package org.kotlintor.crypto

import org.kotlintor.util.SecureRandomSource
import org.kotlintor.util.concat
import org.kotlintor.util.constantTimeEquals
import org.kotlintor.util.hexToBytes
import org.kotlintor.util.toHex
import java.security.MessageDigest

/**
 * Tor control-port RFC2440 S2K (HashedControlPassword `16:` prefix).
 *
 * Encoded form: `16:` + hex(salt[8] ‖ iter_byte ‖ sha1[20]).
 */
object ControlS2k {
    private const val SALT_LEN = 8
    private const val DIGEST_LEN = 20
    private const val SPEC_LEN = SALT_LEN + 1
    /** Default iteration indicator used by `tor --hash-password` (hash ~64 KiB). */
    const val DEFAULT_ITER_BYTE: Int = 96

    fun rfc2440(secret: ByteArray, specifier: ByteArray): ByteArray {
        require(specifier.size >= SPEC_LEN)
        val c = specifier[8].toInt() and 0xff
        var count = ((16 + (c and 15)).toLong() shl ((c ushr 4) + 6)).toInt()
        val tmp = concat(specifier.copyOfRange(0, SALT_LEN), secret)
        val d = MessageDigest.getInstance("SHA-1")
        while (count > 0) {
            val n = minOf(count, tmp.size)
            d.update(tmp, 0, n)
            count -= n
        }
        return d.digest()
    }

    /** Produce a torrc `HashedControlPassword` value for [password]. */
    fun hashPassword(password: String, iterByte: Int = DEFAULT_ITER_BYTE): String {
        val salt = SecureRandomSource.nextBytes(SALT_LEN)
        val spec = concat(salt, byteArrayOf(iterByte.toByte()))
        val digest = rfc2440(password.toByteArray(Charsets.UTF_8), spec)
        return "16:" + concat(spec, digest).toHex()
    }

    fun verify(password: String, hashedControlPassword: String): Boolean {
        val raw = hashedControlPassword.trim()
        require(raw.startsWith("16:", ignoreCase = true)) {
            "only RFC2440 HashedControlPassword (16:) is supported"
        }
        val decoded = hexToBytes(raw.substring(3))
        require(decoded.size == SPEC_LEN + DIGEST_LEN) {
            "invalid HashedControlPassword length"
        }
        val expected = decoded.copyOfRange(SPEC_LEN, decoded.size)
        val got = rfc2440(password.toByteArray(Charsets.UTF_8), decoded)
        return constantTimeEquals(expected, got)
    }
}
