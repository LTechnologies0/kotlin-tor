package org.kotlintor.crypto

import org.kotlintor.util.SecureRandomSource

/**
 * CREATE_FAST onion handshake (C Tor `onion_fast.c`).
 *
 * Inventory: `L1:core/crypto/onion_fast.c`
 *
 * Implementation: [CreateFast]. This object is the naming-aligned entry surface.
 */
object OnionFast {
    const val HASH_LEN: Int = CreateFast.HASH_LEN

    fun clientBegin(x: ByteArray = SecureRandomSource.nextBytes(HASH_LEN)) =
        CreateFast.clientBegin(x)

    fun clientFinish(state: CreateFast.ClientState, serverHandshake: ByteArray): CreateFast.Result =
        CreateFast.clientFinish(state, serverHandshake)

    fun serverRespond(
        clientX: ByteArray,
        y: ByteArray = SecureRandomSource.nextBytes(HASH_LEN),
    ): Pair<ByteArray, CreateFast.Result> = CreateFast.serverRespond(clientX, y)

    fun kdfTor(seed: ByteArray, length: Int = 92): ByteArray = CreateFast.kdfTor(seed, length)

    fun derive(seed: ByteArray): CreateFast.Result = CreateFast.derive(seed)

    // --- C Tor `onion_fast.h` op aliases (L3) ---

    /** C Tor `fast_onionskin_create` / client begin. */
    fun fastOnionskinCreate(x: ByteArray = SecureRandomSource.nextBytes(HASH_LEN)) = clientBegin(x)

    /** C Tor `fast_client_handshake`. */
    fun fastClientHandshake(state: CreateFast.ClientState, serverHandshake: ByteArray) =
        clientFinish(state, serverHandshake)

    /** C Tor `fast_server_handshake`. */
    fun fastServerHandshake(clientX: ByteArray, y: ByteArray = SecureRandomSource.nextBytes(HASH_LEN)) =
        serverRespond(clientX, y)

    /** C Tor `fast_handshake_state_free_`. */
    fun fastHandshakeStateFree(state: CreateFast.ClientState) {
        state.x.fill(0)
    }
}
