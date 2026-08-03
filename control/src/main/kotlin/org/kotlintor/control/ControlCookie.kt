package org.kotlintor.control

import org.kotlintor.crypto.Digests
import org.kotlintor.util.concat

/**
 * Control-port SAFECOOKIE (control-spec AUTHCHALLENGE / AUTHENTICATE).
 *
 * ServerHash = HMAC-SHA256(server-to-controller constant, cookie|clientNonce|serverNonce)
 * ClientHash = HMAC-SHA256(controller-to-server constant, cookie|clientNonce|serverNonce)
 */
object ControlCookie {
    private val SERVER_TO_CONTROLLER =
        "Tor safe cookie authentication server-to-controller hash".toByteArray()
    private val CONTROLLER_TO_SERVER =
        "Tor safe cookie authentication controller-to-server hash".toByteArray()

    const val COOKIE_LEN = 32
    const val SERVER_NONCE_LEN = 32
    const val HASH_LEN = 32

    fun serverHash(cookie: ByteArray, clientNonce: ByteArray, serverNonce: ByteArray): ByteArray =
        Digests.hmacSha256(SERVER_TO_CONTROLLER, concat(cookie, clientNonce, serverNonce))

    fun clientHash(cookie: ByteArray, clientNonce: ByteArray, serverNonce: ByteArray): ByteArray =
        Digests.hmacSha256(CONTROLLER_TO_SERVER, concat(cookie, clientNonce, serverNonce))

    /** @deprecated use [clientHash] — kept name for older call sites. */
    fun hmacChallenge(cookie: ByteArray, clientNonce: ByteArray, serverNonce: ByteArray): ByteArray =
        clientHash(cookie, clientNonce, serverNonce)
}
