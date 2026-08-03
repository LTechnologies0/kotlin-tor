package org.kotlintor.hs

import org.kotlintor.crypto.Ed25519Keys
import org.kotlintor.util.concat
import org.kotlintor.util.u16be

/**
 * ESTABLISH_INTRO cell body (rend-spec EST_INTRO, AUTH_KEY_TYPE=Ed25519).
 */
object HsEstablishIntro {
    private val SIG_PREFIX = "Tor establish-intro cell v1".toByteArray()

    fun build(
        authPublicKey: ByteArray,
        authPrivateKey: ByteArray,
        circuitKh: ByteArray,
    ): ByteArray {
        require(authPublicKey.size == 32)
        require(circuitKh.size == 20)
        val preamble = concat(
            byteArrayOf(0x02), // AUTH_KEY_TYPE Ed25519
            u16be(32),
            authPublicKey,
            byteArrayOf(0), // N_EXTENSIONS
        )
        val handshakeAuth = HsNtor.hsMac(circuitKh, preamble)
        val toSign = concat(SIG_PREFIX, preamble, handshakeAuth)
        val sig = Ed25519Keys.sign(authPrivateKey, toSign)
        return concat(preamble, handshakeAuth, u16be(sig.size), sig)
    }
}
