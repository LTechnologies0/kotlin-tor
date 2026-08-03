package org.kotlintor.crypto

import org.kotlintor.util.concat
import org.kotlintor.util.secureWipe

/** Server-side ntor for self-test / local vectors. */
object NtorServer {
    data class Reply(val handshake: ByteArray, val result: Ntor.Result)

    fun respond(
        identity: ByteArray,
        onionPrivate: ByteArray,
        onionPublic: ByteArray,
        clientHandshake: ByteArray,
    ): Reply {
        require(clientHandshake.size == 84)
        val id = clientHandshake.copyOfRange(0, 20)
        val keyId = clientHandshake.copyOfRange(20, 52)
        val clientPk = clientHandshake.copyOfRange(52, 84)
        check(id.contentEquals(identity)) { "NODEID mismatch" }
        check(keyId.contentEquals(onionPublic)) { "KEYID mismatch" }

        val kp = Curve25519.generateKeyPair()
        val secretXy = Curve25519.sharedSecret(kp.privateKey, clientPk)
        val secretXb = Curve25519.sharedSecret(onionPrivate, clientPk)
        val secretInput = concat(secretXy, secretXb, identity, onionPublic, clientPk, kp.publicKey, PROTOID)
        val keySeed = Digests.hmacSha256(T_KEY, secretInput)
        val verify = Digests.hmacSha256(T_VERIFY, secretInput)
        val authInput = concat(verify, identity, onionPublic, kp.publicKey, clientPk, PROTOID, "Server".toByteArray())
        val auth = Digests.hmacSha256(T_MAC, authInput)
        val keys = Hkdf.expand(keySeed, M_EXPAND, 92)
        secretXy.secureWipe()
        secretXb.secureWipe()
        secretInput.secureWipe()
        return Reply(
            handshake = concat(kp.publicKey, auth),
            result = Ntor.Result(
                keySeed = keySeed,
                verify = verify,
                auth = auth,
                forwardDigest = keys.copyOfRange(0, 20),
                backwardDigest = keys.copyOfRange(20, 40),
                forwardKey = keys.copyOfRange(40, 56),
                backwardKey = keys.copyOfRange(56, 72),
                kh = keys.copyOfRange(72, 92),
            ),
        )
    }

    private val PROTOID = "ntor-curve25519-sha256-1".toByteArray()
    private val T_MAC = concat(PROTOID, ":mac".toByteArray())
    private val T_KEY = concat(PROTOID, ":key_extract".toByteArray())
    private val T_VERIFY = concat(PROTOID, ":verify".toByteArray())
    private val M_EXPAND = concat(PROTOID, ":key_expand".toByteArray())
}
