package org.kotlintor.crypto

import org.kotlintor.circuit.CircuitExtensions
import org.kotlintor.util.SecureRandomSource
import org.kotlintor.util.concat

/**
 * Prop364 CreateOnehop — CREATE2 handshake replacing CREATE_FAST for one-hop dir circuits.
 *
 * Request:  X(32) | extensions
 * Response: Y(32) | extensions
 * KDF: SHAKE256(ENCAP("CreateOneHop") | X | Y) → tor1 keystream (Df|Db|Kf|Kb|KH).
 *
 * HTYPE is provisional (proposal reserves a value; network has not assigned yet).
 * Clients MUST NOT put this in EXTEND2; relays MUST reject EXTEND2 containing it.
 */
object CreateOnehop {
    /** Provisional CREATE2 HTYPE until authorities assign (prop364 appendix). */
    const val HTYPE: Int = 4

    private val TAG = "CreateOneHop".toByteArray()

    data class ClientState(
        val x: ByteArray,
        val clientExtensions: ByteArray,
    )

    data class Result(
        val serverMessage: ByteArray,
        val keystream: ByteArray,
    )

    fun clientBegin(clientExtensions: ByteArray = CircuitExtensions.encode(emptyList())): Pair<ClientState, ByteArray> {
        val x = SecureRandomSource.nextBytes(32)
        val hs = concat(x, clientExtensions)
        return ClientState(x, clientExtensions) to hs
    }

    fun clientFinish(state: ClientState, serverHandshake: ByteArray, keystreamLen: Int = 92): Result {
        require(serverHandshake.size >= 33) { "CreateOnehop response too short" }
        val y = serverHandshake.copyOfRange(0, 32)
        val sm = serverHandshake.copyOfRange(32, serverHandshake.size)
        val ks = kdf(state.x, y, keystreamLen)
        return Result(sm, ks)
    }

    fun serverRespond(
        clientHandshake: ByteArray,
        y: ByteArray = SecureRandomSource.nextBytes(32),
        serverExtensions: ByteArray = CircuitExtensions.encode(emptyList()),
        keystreamLen: Int = 92,
    ): Pair<ByteArray, ByteArray> {
        require(clientHandshake.size >= 33) { "CreateOnehop request too short" }
        val x = clientHandshake.copyOfRange(0, 32)
        // Extensions follow; decoded for CC reply by caller if needed.
        val response = concat(y, serverExtensions)
        val ks = kdf(x, y, keystreamLen)
        return response to ks
    }

    fun clientExtensions(clientHandshake: ByteArray): ByteArray {
        if (clientHandshake.size <= 32) return byteArrayOf(0)
        return clientHandshake.copyOfRange(32, clientHandshake.size)
    }

    private fun kdf(x: ByteArray, y: ByteArray, outLen: Int): ByteArray =
        Shake256.xof(concat(NtorV3.encap(TAG), x, y), outLen)
}
