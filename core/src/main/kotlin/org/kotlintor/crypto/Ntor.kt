package org.kotlintor.crypto

import org.kotlintor.util.concat
import org.kotlintor.util.secureWipe

/**
 * ntor handshake (tor-spec CREATE2 HTYPE=2).
 * Spec: https://spec.torproject.org/tor-spec/create-created-cells.html
 */
object Ntor {
    const val HTYPE: Int = 2
    private val PROTOID = "ntor-curve25519-sha256-1".toByteArray()
    private val T_MAC = concat(PROTOID, ":mac".toByteArray())
    private val T_KEY = concat(PROTOID, ":key_extract".toByteArray())
    private val T_VERIFY = concat(PROTOID, ":verify".toByteArray())
    private val M_EXPAND = concat(PROTOID, ":key_expand".toByteArray())

    data class ClientState(
        val secretKey: ByteArray,
        val publicKey: ByteArray,
        val handshake: ByteArray,
    )

    data class Result(
        val keySeed: ByteArray,
        val verify: ByteArray,
        val auth: ByteArray,
        val forwardDigest: ByteArray,
        val backwardDigest: ByteArray,
        val forwardKey: ByteArray,
        val backwardKey: ByteArray,
        /** Circuit binding / KH (20 bytes) — used by ESTABLISH_INTRO HANDSHAKE_AUTH. */
        val kh: ByteArray,
    )

    fun clientHandshake(
        identity: ByteArray,
        onionKey: ByteArray,
    ): ClientState {
        require(identity.size == 20) { "RSA identity fingerprint must be 20 bytes" }
        require(onionKey.size == 32)
        val kp = Curve25519.generateKeyPair()
        val handshake = concat(identity, onionKey, kp.publicKey)
        return ClientState(kp.privateKey, kp.publicKey, handshake)
    }

    fun clientFinish(
        state: ClientState,
        identity: ByteArray,
        onionKey: ByteArray,
        serverHandshake: ByteArray,
    ): Result {
        require(serverHandshake.size == 64) { "CREATED2 ntor payload must be 64 bytes" }
        val y = serverHandshake.copyOfRange(0, 32)
        val auth = serverHandshake.copyOfRange(32, 64)

        val secretXy = Curve25519.sharedSecret(state.secretKey, y)
        val secretXb = Curve25519.sharedSecret(state.secretKey, onionKey)
        val secretInput = concat(secretXy, secretXb, identity, onionKey, state.publicKey, y, PROTOID)
        val keySeed = Digests.hmacSha256(T_KEY, secretInput)
        val verify = Digests.hmacSha256(T_VERIFY, secretInput)
        val authInput = concat(verify, identity, onionKey, y, state.publicKey, PROTOID, "Server".toByteArray())
        val expectedAuth = Digests.hmacSha256(T_MAC, authInput)
        check(expectedAuth.contentEquals(auth)) { "ntor AUTH mismatch" }

        // Df(20)|Db(20)|Kf(16)|Kb(16)|KH(20) = 92
        val keys = Hkdf.expand(keySeed, M_EXPAND, 92)
        secretXy.secureWipe()
        secretXb.secureWipe()
        secretInput.secureWipe()
        return Result(
            keySeed = keySeed,
            verify = verify,
            auth = auth,
            forwardDigest = keys.copyOfRange(0, 20),
            backwardDigest = keys.copyOfRange(20, 40),
            forwardKey = keys.copyOfRange(40, 56),
            backwardKey = keys.copyOfRange(56, 72),
            kh = keys.copyOfRange(72, 92),
        )
    }
}
