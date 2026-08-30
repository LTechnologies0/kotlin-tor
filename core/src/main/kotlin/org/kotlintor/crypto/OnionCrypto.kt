package org.kotlintor.crypto

/**
 * Onion handshake dispatch (C Tor `onion_crypto.c`).
 *
 * Inventory: `L1:core/crypto/onion_crypto.c`
 *
 * Selects CREATE_FAST / ntor / ntor-v3 via [HandshakeType] and delegates to
 * [OnionFast], [OnionNtor], [OnionNtorV3].
 */
object OnionCrypto {
    /** C Tor `ONION_HANDSHAKE_TYPE_*`. */
    object HandshakeType {
        const val TAP: Int = 0x0000
        const val FAST: Int = 0x0001
        const val NTOR: Int = 0x0002
        const val NTOR_V3: Int = 0x0003
    }

    data class CircuitParams(
        val ccEnabled: Boolean = false,
        val sendmeIncCells: Int = 31,
        val cryptoAlg: Int = 0, // 0 = tor1
        val cellFmt: Int = 0,
    )

    sealed class ClientState {
        data class Fast(val inner: CreateFast.ClientState) : ClientState()
    }

    fun handshakeName(type: Int): String = when (type) {
        HandshakeType.TAP -> "tap"
        HandshakeType.FAST -> "fast"
        HandshakeType.NTOR -> "ntor"
        HandshakeType.NTOR_V3 -> "ntor3"
        else -> "unknown"
    }

    fun isSupported(type: Int): Boolean =
        type == HandshakeType.FAST || type == HandshakeType.NTOR || type == HandshakeType.NTOR_V3

    /** C Tor `onion_skin_create` for CREATE_FAST. */
    fun onionSkinCreateFast(): Pair<ClientState.Fast, ByteArray> {
        val (st, skin) = OnionFast.clientBegin()
        return ClientState.Fast(st) to skin
    }

    /** C Tor `onion_skin_server_handshake` for CREATE_FAST. */
    fun onionSkinServerFast(onionSkin: ByteArray): Pair<ByteArray, CreateFast.Result> =
        OnionFast.serverRespond(onionSkin)

    /** C Tor `onion_skin_client_handshake` for CREATE_FAST. */
    fun onionSkinClientFast(state: ClientState.Fast, reply: ByteArray): CreateFast.Result =
        OnionFast.clientFinish(state.inner, reply)

    fun onionSkinCreate(type: Int): Pair<ClientState, ByteArray> = when (type) {
        HandshakeType.FAST -> onionSkinCreateFast()
        else -> error("onion_skin_create unsupported type=${handshakeName(type)}")
    }

    /** C Tor `onion_skin_create` / `onion_skin_client_handshake` / `onion_skin_server_handshake` (FAST). */
    fun onionSkinCreate(): Pair<ClientState.Fast, ByteArray> = onionSkinCreateFast()

    fun onionSkinClientHandshake(state: ClientState.Fast, reply: ByteArray): CreateFast.Result =
        onionSkinClientFast(state, reply)

    fun onionSkinServerHandshake(onionSkin: ByteArray): Pair<ByteArray, CreateFast.Result> =
        onionSkinServerFast(onionSkin)

    /** C Tor `onion_handshake_state_release`. */
    fun onionHandshakeStateRelease(state: ClientState) {
        when (state) {
            is ClientState.Fast -> state.inner.x.fill(0)
        }
    }

    data class ServerOnionKeys(
        val identity: ByteArray = ByteArray(20),
        val ntorOnionKey: ByteArray = ByteArray(32),
        val ntorOnionSecret: ByteArray = ByteArray(32),
    )

    /** C Tor `server_onion_keys_new` / `server_onion_keys_free_`. */
    fun serverOnionKeysNew(): ServerOnionKeys {
        val kp = Curve25519.generateKeyPair()
        return ServerOnionKeys(
            identity = Digests.sha1(kp.publicKey),
            ntorOnionKey = kp.publicKey,
            ntorOnionSecret = kp.privateKey,
        )
    }

    fun serverOnionKeysFree(keys: ServerOnionKeys) {
        keys.identity.fill(0)
        keys.ntorOnionKey.fill(0)
        keys.ntorOnionSecret.fill(0)
    }

    /** C Tor `trn_extension_find` — scan ntor-v3 style extension list. */
    fun trnExtensionFind(extensions: ByteArray, type: Int): ByteArray? {
        if (extensions.isEmpty()) return null
        var o = 0
        val n = extensions[o].toInt() and 0xff
        o += 1
        repeat(n) {
            if (o + 2 > extensions.size) return null
            val t = extensions[o].toInt() and 0xff
            val len = extensions[o + 1].toInt() and 0xff
            o += 2
            if (o + len > extensions.size) return null
            val body = extensions.copyOfRange(o, o + len)
            o += len
            if (t == type) return body
        }
        return null
    }
}
