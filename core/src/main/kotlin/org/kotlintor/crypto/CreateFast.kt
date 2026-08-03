package org.kotlintor.crypto

import org.kotlintor.util.SecureRandomSource

/**
 * CREATE_FAST / CREATED_FAST (tor-spec) for one-hop directory circuits.
 *
 * Client sends random X (20). Server replies Y (20) ‖ KH (20).
 * Shared seed K = X‖Y; keys via [kdfTor].
 */
object CreateFast {
    const val HASH_LEN = 20

    data class Result(
        val kh: ByteArray,
        val forwardDigest: ByteArray,
        val backwardDigest: ByteArray,
        val forwardKey: ByteArray,
        val backwardKey: ByteArray,
    )

    data class ClientState(val x: ByteArray)

    fun clientBegin(x: ByteArray = SecureRandomSource.nextBytes(HASH_LEN)): Pair<ClientState, ByteArray> {
        require(x.size == HASH_LEN)
        return ClientState(x.copyOf()) to x.copyOf()
    }

    fun clientFinish(state: ClientState, serverHandshake: ByteArray): Result {
        require(serverHandshake.size >= HASH_LEN * 2) { "CREATED_FAST too short" }
        val y = serverHandshake.copyOfRange(0, HASH_LEN)
        val khWire = serverHandshake.copyOfRange(HASH_LEN, HASH_LEN * 2)
        val keys = derive(state.x + y)
        check(keys.kh.contentEquals(khWire)) { "CREATE_FAST KH mismatch" }
        return keys
    }

    fun serverRespond(clientX: ByteArray, y: ByteArray = SecureRandomSource.nextBytes(HASH_LEN)): Pair<ByteArray, Result> {
        require(clientX.size == HASH_LEN && y.size == HASH_LEN)
        val keys = derive(clientX + y)
        val handshake = y + keys.kh
        return handshake to keys
    }

    /**
     * KDF-TOR: Ki = SHA1(K ‖ i) for i = 0,1,… concatenated.
     * Layout: KH(20)‖Df(20)‖Db(20)‖Kf(16)‖Kb(16).
     */
    fun kdfTor(seed: ByteArray, length: Int = 92): ByteArray {
        val out = ByteArray(length)
        var offset = 0
        var i = 0
        while (offset < length) {
            val block = Digests.sha1(seed + byteArrayOf(i.toByte()))
            val n = minOf(block.size, length - offset)
            block.copyInto(out, offset, 0, n)
            offset += n
            i++
            check(i < 256) { "KDF-TOR overflow" }
        }
        return out
    }

    fun derive(seed: ByteArray): Result {
        val ks = kdfTor(seed, 92)
        return Result(
            kh = ks.copyOfRange(0, 20),
            forwardDigest = ks.copyOfRange(20, 40),
            backwardDigest = ks.copyOfRange(40, 60),
            forwardKey = ks.copyOfRange(60, 76),
            backwardKey = ks.copyOfRange(76, 92),
        )
    }
}
