package org.kotlintor.hs

import org.kotlintor.crypto.AesCtr
import org.kotlintor.crypto.Curve25519
import org.kotlintor.crypto.Digests
import org.kotlintor.crypto.Shake256
import org.kotlintor.util.concat
import org.kotlintor.util.u16be
import org.kotlintor.util.u64be

/**
 * Hidden-service ntor (rend-spec NTOR-WITH-EXTRA-DATA).
 * PROTOID = "tor-hs-ntor-curve25519-sha3-256-1"
 *
 * MAC(k, m) = SHA3-256(htonll(len(k)) | k | m) — not HMAC.
 * Intro KDF = SHAKE256(intro_secret | t_hsenc | info).
 */
object HsNtor {
    private val PROTOID = "tor-hs-ntor-curve25519-sha3-256-1".toByteArray()
    private val T_HSENC = concat(PROTOID, ":hs_key_extract".toByteArray())
    private val T_HSVERIFY = concat(PROTOID, ":hs_verify".toByteArray())
    private val T_HSMAC = concat(PROTOID, ":hs_mac".toByteArray())
    private val M_HSEXPAND = concat(PROTOID, ":hs_key_expand".toByteArray())

    const val INTRO1_TARGET_LEN = 490
    const val S_KEY_LEN = 32
    const val MAC_LEN = 32

    /** rend-spec MAC: H(htonll(len(k)) | k | m) with H = SHA3-256. */
    fun hsMac(key: ByteArray, msg: ByteArray): ByteArray =
        Digests.sha3_256(concat(u64be(key.size.toLong()), key, msg))

    data class ClientState(
        val clientSk: ByteArray,
        val clientPk: ByteArray,
        val serviceEncKey: ByteArray,
        val authKey: ByteArray,
        val subcredential: ByteArray,
    )

    data class HopKeyMaterial(
        val forwardDigest: ByteArray,
        val backwardDigest: ByteArray,
        val forwardKey: ByteArray,
        val backwardKey: ByteArray,
    )

    fun clientBegin(
        serviceEncKey: ByteArray,
        authKey: ByteArray,
        subcredential: ByteArray,
        clientSk: ByteArray? = null,
    ): ClientState {
        require(serviceEncKey.size == 32 && authKey.size == 32 && subcredential.size == 32)
        val sk = clientSk ?: Curve25519.generateKeyPair().privateKey
        val pk = Curve25519.publicFromPrivate(sk)
        return ClientState(sk, pk, serviceEncKey, authKey, subcredential)
    }

    fun introduceKeys(state: ClientState): Pair<ByteArray, ByteArray> {
        val bx = Curve25519.sharedSecret(state.clientSk, state.serviceEncKey)
        val secretInput = concat(
            bx,
            state.authKey,
            state.clientPk,
            state.serviceEncKey,
            PROTOID,
            T_HSENC,
            M_HSEXPAND,
            state.subcredential,
        )
        val hsKeys = Shake256.xof(secretInput, S_KEY_LEN + MAC_LEN)
        return hsKeys.copyOfRange(0, S_KEY_LEN) to hsKeys.copyOfRange(S_KEY_LEN, S_KEY_LEN + MAC_LEN)
    }

    /**
     * Build ENCRYPTED portion: CLIENT_PK | ENCRYPTED_DATA | MAC.
     * [introHeader] is LEGACY_KEY_ID…N_EXTENSIONS (everything before ENCRYPTED).
     */
    fun clientEncryptIntro(
        state: ClientState,
        introHeader: ByteArray,
        plaintext: ByteArray,
        targetLen: Int = INTRO1_TARGET_LEN,
    ): ByteArray {
        val (encKey, macKey) = introduceKeys(state)
        val encOverhead = 32 + MAC_LEN
        val padTarget = (targetLen - introHeader.size - encOverhead).coerceAtLeast(plaintext.size)
        val padded = plaintext.copyOf(padTarget)
        val ciphertext = AesCtr(encKey, ByteArray(16)).process(padded)
        val macBody = concat(introHeader, state.clientPk, ciphertext)
        val mac = hsMac(macKey, macBody)
        return concat(state.clientPk, ciphertext, mac)
    }

    fun buildIntroHeader(authKey: ByteArray): ByteArray {
        require(authKey.size == 32)
        return concat(
            ByteArray(20), // LEGACY_KEY_ID
            byteArrayOf(0x02),
            u16be(32),
            authKey,
            byteArrayOf(0), // N_EXTENSIONS
        )
    }

    fun buildIntroducePlaintext(
        rendezvousCookie: ByteArray,
        rendOnionKey: ByteArray,
        rendLinkSpecifiers: List<ByteArray>,
    ): ByteArray {
        require(rendezvousCookie.size == 20)
        require(rendOnionKey.size == 32)
        val onion = byteArrayOf(0x01) + u16be(32) + rendOnionKey
        val nspec = byteArrayOf(rendLinkSpecifiers.size.toByte())
        val specs = rendLinkSpecifiers.fold(ByteArray(0)) { acc, s -> acc + s }
        return concat(rendezvousCookie, byteArrayOf(0), onion, nspec, specs)
    }

    /** Finish after RENDEZVOUS2 HANDSHAKE_INFO = Y | AUTH (64 bytes). */
    fun clientFinishRendezvous(state: ClientState, serverHandshake: ByteArray): HopKeyMaterial {
        require(serverHandshake.size >= 64) { "RENDEZVOUS2 handshake too short" }
        val y = serverHandshake.copyOfRange(0, 32)
        val auth = serverHandshake.copyOfRange(32, 64)
        val xy = Curve25519.sharedSecret(state.clientSk, y)
        val xb = Curve25519.sharedSecret(state.clientSk, state.serviceEncKey)
        val secretInput = concat(
            xy, xb, state.authKey, state.serviceEncKey, state.clientPk, y, PROTOID,
        )
        val ntorKeySeed = hsMac(secretInput, T_HSENC)
        val verify = hsMac(secretInput, T_HSVERIFY)
        val authInput = concat(
            verify, state.authKey, state.serviceEncKey, y, state.clientPk, PROTOID, "Server".toByteArray(),
        )
        val expectAuth = hsMac(authInput, T_HSMAC)
        check(expectAuth.contentEquals(auth)) { "hs-ntor AUTH mismatch" }
        return expandRendezvousKeys(ntorKeySeed)
    }

    data class IntroPlaintext(
        val rendezvousCookie: ByteArray,
        val extensions: ByteArray,
        val rendOnionKey: ByteArray,
        val rendLinkSpecifiers: ByteArray,
        val raw: ByteArray,
    )

    data class ServiceIntroResult(
        /** Y ‖ AUTH for RENDEZVOUS1 HANDSHAKE_INFO. */
        val handshakeInfo: ByteArray,
        val hopKeys: HopKeyMaterial,
        val plaintext: IntroPlaintext,
        val clientPk: ByteArray,
    )

    /**
     * Service-side INTRODUCE2 decrypt + hs-ntor completion.
     * [encrypted] is CLIENT_PK | ENCRYPTED_DATA | MAC (the ENCRYPTED field).
     */
    fun serviceReceiveIntro(
        encPrivate: ByteArray,
        encPublic: ByteArray,
        authKey: ByteArray,
        subcredential: ByteArray,
        introHeader: ByteArray,
        encrypted: ByteArray,
        ephemeralSk: ByteArray? = null,
    ): ServiceIntroResult {
        require(encrypted.size > 32 + MAC_LEN) { "ENCRYPTED field too short" }
        val clientPk = encrypted.copyOfRange(0, 32)
        val mac = encrypted.copyOfRange(encrypted.size - MAC_LEN, encrypted.size)
        val ciphertext = encrypted.copyOfRange(32, encrypted.size - MAC_LEN)

        val bx = Curve25519.sharedSecret(encPrivate, clientPk)
        val secretInput = concat(
            bx, authKey, clientPk, encPublic, PROTOID, T_HSENC, M_HSEXPAND, subcredential,
        )
        val hsKeys = Shake256.xof(secretInput, S_KEY_LEN + MAC_LEN)
        val encKey = hsKeys.copyOfRange(0, S_KEY_LEN)
        val macKey = hsKeys.copyOfRange(S_KEY_LEN, S_KEY_LEN + MAC_LEN)
        val expectMac = hsMac(macKey, concat(introHeader, clientPk, ciphertext))
        check(expectMac.contentEquals(mac)) { "INTRODUCE2 MAC mismatch" }

        val plain = AesCtr(encKey, ByteArray(16)).process(ciphertext)
        val parsed = parseIntroducePlaintext(plain)

        val ySk = ephemeralSk ?: Curve25519.generateKeyPair().privateKey
        val yPk = Curve25519.publicFromPrivate(ySk)
        val xy = Curve25519.sharedSecret(ySk, clientPk)
        val xb = Curve25519.sharedSecret(encPrivate, clientPk)
        val rendSecret = concat(xy, xb, authKey, encPublic, clientPk, yPk, PROTOID)
        val ntorKeySeed = hsMac(rendSecret, T_HSENC)
        val verify = hsMac(rendSecret, T_HSVERIFY)
        val authInput = concat(
            verify, authKey, encPublic, yPk, clientPk, PROTOID, "Server".toByteArray(),
        )
        val authMac = hsMac(authInput, T_HSMAC)
        val hopKeys = expandRendezvousKeys(ntorKeySeed).swapped()
        return ServiceIntroResult(
            handshakeInfo = concat(yPk, authMac),
            hopKeys = hopKeys,
            plaintext = parsed,
            clientPk = clientPk,
        )
    }

    fun parseIntroducePlaintext(plain: ByteArray): IntroPlaintext {
        require(plain.size >= 20 + 1 + 1 + 2 + 32 + 1) { "intro plaintext too short" }
        var o = 0
        val cookie = plain.copyOfRange(o, o + 20); o += 20
        val nExt = plain[o].toInt() and 0xff; o += 1
        // skip extensions (type, len_u8, body)*
        val extStart = o
        repeat(nExt) {
            require(o + 2 <= plain.size) { "truncated intro extension" }
            val len = plain[o + 1].toInt() and 0xff
            o += 2 + len
        }
        val extensions = plain.copyOfRange(extStart, o)
        require(plain[o].toInt() and 0xff == 0x01) { "expected ONION_KEY_TYPE ntor" }
        o += 1
        val okLen = ((plain[o].toInt() and 0xff) shl 8) or (plain[o + 1].toInt() and 0xff)
        o += 2
        require(okLen == 32) { "unexpected onion key len $okLen" }
        val onion = plain.copyOfRange(o, o + 32); o += 32
        val nSpec = plain[o].toInt() and 0xff; o += 1
        val specStart = o
        repeat(nSpec) {
            require(o + 2 <= plain.size) { "truncated link specifier" }
            val len = plain[o + 1].toInt() and 0xff
            o += 2 + len
        }
        val specs = plain.copyOfRange(specStart - 1, o) // include nspec byte
        return IntroPlaintext(cookie, extensions, onion, specs, plain)
    }

    private fun expandRendezvousKeys(ntorKeySeed: ByteArray): HopKeyMaterial {
        val expanded = Shake256.xof(concat(ntorKeySeed, M_HSEXPAND), 128)
        return HopKeyMaterial(
            forwardDigest = expanded.copyOfRange(0, 32),
            backwardDigest = expanded.copyOfRange(32, 64),
            forwardKey = expanded.copyOfRange(64, 96),
            backwardKey = expanded.copyOfRange(96, 128),
        )
    }

    /** Service sees client's forward as its backward (and vice versa). */
    private fun HopKeyMaterial.swapped(): HopKeyMaterial =
        HopKeyMaterial(
            forwardDigest = backwardDigest,
            backwardDigest = forwardDigest,
            forwardKey = backwardKey,
            backwardKey = forwardKey,
        )

    // --- C Tor `hs_ntor.h` op aliases (L3) ---

    /** C Tor `hs_ntor_client_get_introduce1_keys`. */
    fun hsNtorClientGetIntroduce1Keys(state: ClientState): Pair<ByteArray, ByteArray> =
        introduceKeys(state)

    /** C Tor `hs_ntor_service_get_introduce1_keys` — same KDF as client intro keys. */
    fun hsNtorServiceGetIntroduce1Keys(
        encPrivate: ByteArray,
        encPublic: ByteArray,
        authKey: ByteArray,
        subcredential: ByteArray,
        clientPk: ByteArray,
    ): Pair<ByteArray, ByteArray> {
        val bx = Curve25519.sharedSecret(encPrivate, clientPk)
        val secretInput = concat(
            bx, authKey, clientPk, encPublic, PROTOID, T_HSENC, M_HSEXPAND, subcredential,
        )
        val hsKeys = Shake256.xof(secretInput, S_KEY_LEN + MAC_LEN)
        return hsKeys.copyOfRange(0, S_KEY_LEN) to hsKeys.copyOfRange(S_KEY_LEN, S_KEY_LEN + MAC_LEN)
    }

    /** C Tor `hs_ntor_service_get_introduce1_keys_multi` — one client. */
    fun hsNtorServiceGetIntroduce1KeysMulti(
        encPrivate: ByteArray,
        encPublic: ByteArray,
        authKey: ByteArray,
        subcredential: ByteArray,
        clientPks: List<ByteArray>,
    ): List<Pair<ByteArray, ByteArray>> =
        clientPks.map { hsNtorServiceGetIntroduce1Keys(encPrivate, encPublic, authKey, subcredential, it) }

    /** C Tor `hs_ntor_circuit_key_expansion`. */
    fun hsNtorCircuitKeyExpansion(ntorKeySeed: ByteArray): HopKeyMaterial =
        expandRendezvousKeys(ntorKeySeed)

    /** C Tor `hs_ntor_client_get_rendezvous1_keys` / finish REND2. */
    fun hsNtorClientGetRendezvous1Keys(state: ClientState, serverHandshake: ByteArray): HopKeyMaterial =
        clientFinishRendezvous(state, serverHandshake)

    /** C Tor `hs_ntor_service_get_rendezvous1_keys` — from service intro result. */
    fun hsNtorServiceGetRendezvous1Keys(result: ServiceIntroResult): HopKeyMaterial = result.hopKeys

    /** C Tor `hs_ntor_client_rendezvous2_mac_is_good`. */
    fun hsNtorClientRendezvous2MacIsGood(state: ClientState, serverHandshake: ByteArray): Boolean =
        runCatching { clientFinishRendezvous(state, serverHandshake) }.isSuccess
}
