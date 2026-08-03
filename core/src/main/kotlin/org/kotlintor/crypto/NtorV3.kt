package org.kotlintor.crypto

import org.kotlintor.util.concat
import org.kotlintor.util.u64be

/**
 * ntor-v3 handshake (tor-spec CREATE2 HTYPE=3 / Relay=4).
 *
 * PROTOID = "ntor3-curve25519-sha3_256-1"
 * Circuit VER = "circuit extend" (Arti/C Tor).
 */
object NtorV3 {
    const val HTYPE: Int = 3
    val CIRCUIT_VERIFICATION: ByteArray = "circuit extend".toByteArray()

    private val PROTOID = "ntor3-curve25519-sha3_256-1".toByteArray()
    private val T_MSGKDF = concat(PROTOID, ":kdf_phase1".toByteArray())
    private val T_MSGMAC = concat(PROTOID, ":msg_mac".toByteArray())
    private val T_KEY_SEED = concat(PROTOID, ":key_seed".toByteArray())
    private val T_VERIFY = concat(PROTOID, ":verify".toByteArray())
    private val T_FINAL = concat(PROTOID, ":kdf_final".toByteArray())
    private val T_AUTH = concat(PROTOID, ":auth_final".toByteArray())

    private const val ENC_KEY_LEN = 32
    private const val MAC_KEY_LEN = 32
    private const val PUB_KEY_LEN = 32
    private const val ID_LEN = 32
    private const val DIGEST_LEN = 32
    private const val MAC_LEN = 32

    /** ENCAP(s) = htonll(len(s)) | s */
    fun encap(s: ByteArray): ByteArray = concat(u64be(s.size.toLong()), s)

    private fun hash(tag: ByteArray, data: ByteArray): ByteArray =
        Digests.sha3_256(concat(encap(tag), data))

    private fun kdf(tag: ByteArray, data: ByteArray, outLen: Int): ByteArray =
        Shake256.xof(concat(encap(tag), data), outLen)

    private fun encrypt(key: ByteArray, msg: ByteArray): ByteArray =
        AesCtr(key, ByteArray(16)).process(msg)

    data class PublicKey(
        /** Ed25519 identity (32 bytes). */
        val id: ByteArray,
        /** Curve25519 ntor onion key. */
        val onionKey: ByteArray,
    ) {
        init {
            require(id.size == ID_LEN && onionKey.size == PUB_KEY_LEN)
        }
    }

    data class ClientState(
        val relay: PublicKey,
        val clientSk: ByteArray,
        val clientPk: ByteArray,
        val bx: ByteArray,
        val msgMac: ByteArray,
        val verification: ByteArray,
    )

    data class Result(
        val serverMessage: ByteArray,
        /** Circuit keystream after ENC_KEY for SM (caller takes Df|Db|Kf|Kb|…). */
        val keystream: ByteArray,
    )

    /**
     * Client CREATE2 handshake body: ID | B | X | encrypted_msg | MAC.
     * [clientSk] optional for test vectors.
     */
    fun clientBegin(
        relay: PublicKey,
        clientMessage: ByteArray,
        verification: ByteArray = CIRCUIT_VERIFICATION,
        clientSk: ByteArray? = null,
    ): Pair<ClientState, ByteArray> {
        val sk = clientSk ?: Curve25519.generateKeyPair().privateKey
        val pk = Curve25519.publicFromPrivate(sk)
        val bx = Curve25519.sharedSecret(sk, relay.onionKey)
        val phase1 = kdf(
            T_MSGKDF,
            concat(bx, relay.id, pk, relay.onionKey, PROTOID, encap(verification)),
            ENC_KEY_LEN + MAC_KEY_LEN,
        )
        val encK1 = phase1.copyOfRange(0, ENC_KEY_LEN)
        val macK1 = phase1.copyOfRange(ENC_KEY_LEN, ENC_KEY_LEN + MAC_KEY_LEN)
        val encrypted = encrypt(encK1, clientMessage)
        val msgMac = Digests.sha3_256(
            concat(encap(T_MSGMAC), encap(macK1), relay.id, relay.onionKey, pk, encrypted),
        )
        val handshake = concat(relay.id, relay.onionKey, pk, encrypted, msgMac)
        val state = ClientState(relay, sk, pk, bx, msgMac, verification.copyOf())
        return state to handshake
    }

    fun clientFinish(
        state: ClientState,
        serverHandshake: ByteArray,
        keystreamLen: Int = 256,
    ): Result {
        require(serverHandshake.size >= PUB_KEY_LEN + DIGEST_LEN) { "ntor-v3 CREATED2 too short" }
        val y = serverHandshake.copyOfRange(0, PUB_KEY_LEN)
        val auth = serverHandshake.copyOfRange(PUB_KEY_LEN, PUB_KEY_LEN + DIGEST_LEN)
        val encryptedMsg = serverHandshake.copyOfRange(PUB_KEY_LEN + DIGEST_LEN, serverHandshake.size)

        val yx = Curve25519.sharedSecret(state.clientSk, y)
        val secretInput = concat(
            yx,
            state.bx,
            state.relay.id,
            state.relay.onionKey,
            state.clientPk,
            y,
            PROTOID,
            encap(state.verification),
        )
        val ntorKeySeed = hash(T_KEY_SEED, secretInput)
        val verify = hash(T_VERIFY, secretInput)
        val expectedAuth = Digests.sha3_256(
            concat(
                encap(T_AUTH),
                verify,
                state.relay.id,
                state.relay.onionKey,
                y,
                state.clientPk,
                state.msgMac,
                encap(encryptedMsg),
                PROTOID,
                "Server".toByteArray(),
            ),
        )
        check(expectedAuth.contentEquals(auth)) { "ntor-v3 AUTH mismatch" }

        val raw = kdf(T_FINAL, ntorKeySeed, ENC_KEY_LEN + keystreamLen)
        val encKey = raw.copyOfRange(0, ENC_KEY_LEN)
        val keystream = raw.copyOfRange(ENC_KEY_LEN, ENC_KEY_LEN + keystreamLen)
        val serverMessage = encrypt(encKey, encryptedMsg)
        return Result(serverMessage, keystream)
    }

    data class ServerReply(
        val handshake: ByteArray,
        val keystream: ByteArray,
        val clientMessage: ByteArray,
    )

    /**
     * Server CREATE2 reply. [serverYSk] optional for test vectors.
     */
    fun serverRespond(
        id: ByteArray,
        onionSk: ByteArray,
        onionPk: ByteArray,
        clientHandshake: ByteArray,
        serverMessage: ByteArray,
        verification: ByteArray = CIRCUIT_VERIFICATION,
        serverYSk: ByteArray? = null,
        keystreamLen: Int = 256,
    ): ServerReply = serverRespond(
        id = id,
        onionSk = onionSk,
        onionPk = onionPk,
        clientHandshake = clientHandshake,
        verification = verification,
        serverYSk = serverYSk,
        keystreamLen = keystreamLen,
        serverMessageFor = { serverMessage },
    )

    fun serverRespond(
        id: ByteArray,
        onionSk: ByteArray,
        onionPk: ByteArray,
        clientHandshake: ByteArray,
        verification: ByteArray = CIRCUIT_VERIFICATION,
        serverYSk: ByteArray? = null,
        keystreamLen: Int = 256,
        serverMessageFor: (clientMessage: ByteArray) -> ByteArray,
    ): ServerReply {
        require(id.size == ID_LEN && onionPk.size == PUB_KEY_LEN)
        require(clientHandshake.size >= ID_LEN + PUB_KEY_LEN + PUB_KEY_LEN + MAC_LEN)
        val nodeId = clientHandshake.copyOfRange(0, ID_LEN)
        val keyId = clientHandshake.copyOfRange(ID_LEN, ID_LEN + PUB_KEY_LEN)
        val clientPk = clientHandshake.copyOfRange(ID_LEN + PUB_KEY_LEN, ID_LEN + 2 * PUB_KEY_LEN)
        val macOff = clientHandshake.size - MAC_LEN
        val encryptedClient = clientHandshake.copyOfRange(ID_LEN + 2 * PUB_KEY_LEN, macOff)
        val msgMac = clientHandshake.copyOfRange(macOff, clientHandshake.size)
        check(nodeId.contentEquals(id)) { "ntor-v3 NODEID mismatch" }
        check(keyId.contentEquals(onionPk)) { "ntor-v3 KEYID mismatch" }

        val xb = Curve25519.sharedSecret(onionSk, clientPk)
        val phase1 = kdf(
            T_MSGKDF,
            concat(xb, id, clientPk, onionPk, PROTOID, encap(verification)),
            ENC_KEY_LEN + MAC_KEY_LEN,
        )
        val encK1 = phase1.copyOfRange(0, ENC_KEY_LEN)
        val macK1 = phase1.copyOfRange(ENC_KEY_LEN, ENC_KEY_LEN + MAC_KEY_LEN)
        val expectedMac = Digests.sha3_256(
            concat(encap(T_MSGMAC), encap(macK1), id, onionPk, clientPk, encryptedClient),
        )
        check(expectedMac.contentEquals(msgMac)) { "ntor-v3 client MAC mismatch" }
        val clientMessage = encrypt(encK1, encryptedClient)
        val serverMessage = serverMessageFor(clientMessage)

        val ySk = serverYSk ?: Curve25519.generateKeyPair().privateKey
        val yPk = Curve25519.publicFromPrivate(ySk)
        val xy = Curve25519.sharedSecret(ySk, clientPk)
        val secretInput = concat(xy, xb, id, onionPk, clientPk, yPk, PROTOID, encap(verification))
        val ntorKeySeed = hash(T_KEY_SEED, secretInput)
        val verify = hash(T_VERIFY, secretInput)
        val raw = kdf(T_FINAL, ntorKeySeed, ENC_KEY_LEN + keystreamLen)
        val encKey = raw.copyOfRange(0, ENC_KEY_LEN)
        val keystream = raw.copyOfRange(ENC_KEY_LEN, ENC_KEY_LEN + keystreamLen)
        val encryptedReply = encrypt(encKey, serverMessage)
        val auth = Digests.sha3_256(
            concat(
                encap(T_AUTH),
                verify,
                id,
                onionPk,
                yPk,
                clientPk,
                msgMac,
                encap(encryptedReply),
                PROTOID,
                "Server".toByteArray(),
            ),
        )
        return ServerReply(
            handshake = concat(yPk, auth, encryptedReply),
            keystream = keystream,
            clientMessage = clientMessage,
        )
    }

    /** Empty client extensions blob: N_EXTENSIONS = 0. */
    fun emptyExtensions(): ByteArray = byteArrayOf(0)

    /** CC_FIELD_REQUEST extension (type 1, empty body) wrapped as N_EXTENSIONS message. */
    fun congestionControlRequest(): ByteArray =
        byteArrayOf(1, 1, 0) // one extension: type=1, len=0
}
