package org.kotlintor.hs

import org.kotlintor.crypto.AesCtr
import org.kotlintor.crypto.Curve25519
import org.kotlintor.crypto.Shake256
import org.kotlintor.util.SecureRandomSource
import org.kotlintor.util.concat
import java.util.Base64

/**
 * Onion service client authorization (x25519) — rend-spec [HS-DESC-ENC] / C Tor
 * `hs_descriptor.c` (`build_descriptor_cookie_keys`, `hs_desc_build_authorized_client`).
 *
 * ```
 * SECRET_SEED = x25519(sk, pk)
 * KEYS = SHAKE256(N_hs_subcred | SECRET_SEED, 40)
 * CLIENT-ID = KEYS[0..7]
 * COOKIE-KEY = KEYS[8..39]
 * encrypted-cookie = AES-256-CTR(COOKIE-KEY, iv) XOR N_hs_desc_enc
 * ```
 *
 * Cookie length matches C Tor (`HS_DESC_DESCRIPTOR_COOKIE_LEN` = 16), not the
 * newer 32-byte `N_hs_desc_enc` wording in the HTML spec.
 */
object HsClientAuth {
    const val CLIENT_ID_LEN: Int = 8
    const val COOKIE_LEN: Int = 16
    const val COOKIE_KEY_LEN: Int = 32
    const val IV_LEN: Int = 16

    data class ClientCred(
        val name: String,
        val privateKey: ByteArray,
        val publicKey: ByteArray,
    )

    /** C Tor `hs_desc_authorized_client_t`. */
    data class AuthClientEntry(
        val clientId: ByteArray,
        val iv: ByteArray,
        val encryptedCookie: ByteArray,
    )

    fun generate(name: String = "client"): ClientCred {
        val kp = Curve25519.generateKeyPair()
        return ClientCred(name, kp.privateKey, kp.publicKey)
    }

    /**
     * C Tor `build_descriptor_cookie_keys` — 40-byte KEYS stream.
     */
    fun buildDescriptorCookieKeys(
        subcredential: ByteArray,
        sk: ByteArray,
        pk: ByteArray,
    ): ByteArray {
        require(subcredential.size == 32) { "subcredential must be 32 bytes" }
        val secretSeed = Curve25519.sharedSecret(sk, pk)
        return Shake256.xof(concat(subcredential, secretSeed), CLIENT_ID_LEN + COOKIE_KEY_LEN)
    }

    /** Derive CLIENT-ID for [clientPublic] under [ephemeralPriv] + [subcredential]. */
    fun clientId(
        subcredential: ByteArray,
        ephemeralPriv: ByteArray,
        clientPublic: ByteArray,
    ): ByteArray =
        buildDescriptorCookieKeys(subcredential, ephemeralPriv, clientPublic)
            .copyOfRange(0, CLIENT_ID_LEN)

    /**
     * Host-side seal: encrypt [cookie] for [clientPub] (C Tor
     * `hs_desc_build_authorized_client`).
     * @return plaintext cookie and the auth-client entry to publish
     */
    fun sealCookie(
        subcredential: ByteArray,
        ephemeralPriv: ByteArray,
        clientPub: ByteArray,
        cookie: ByteArray = SecureRandomSource.nextBytes(COOKIE_LEN),
        iv: ByteArray = SecureRandomSource.nextBytes(IV_LEN),
    ): Pair<ByteArray, AuthClientEntry> {
        require(cookie.size == COOKIE_LEN) { "descriptor cookie must be $COOKIE_LEN bytes" }
        require(iv.size == IV_LEN)
        val keys = buildDescriptorCookieKeys(subcredential, ephemeralPriv, clientPub)
        val clientId = keys.copyOfRange(0, CLIENT_ID_LEN)
        val cookieKey = keys.copyOfRange(CLIENT_ID_LEN, CLIENT_ID_LEN + COOKIE_KEY_LEN)
        val enc = AesCtr(cookieKey, iv).process(cookie)
        return cookie to AuthClientEntry(clientId, iv.copyOf(), enc)
    }

    /**
     * Client recovers cookie (C Tor `decrypt_descriptor_cookie`).
     * Returns null if CLIENT-ID does not match this client key.
     */
    fun openCookie(
        subcredential: ByteArray,
        clientPriv: ByteArray,
        ephemeralPub: ByteArray,
        entry: AuthClientEntry,
    ): ByteArray? {
        require(entry.encryptedCookie.size == COOKIE_LEN)
        require(entry.iv.size == IV_LEN)
        val keys = buildDescriptorCookieKeys(subcredential, clientPriv, ephemeralPub)
        val expectId = keys.copyOfRange(0, CLIENT_ID_LEN)
        if (!expectId.contentEquals(entry.clientId)) return null
        val cookieKey = keys.copyOfRange(CLIENT_ID_LEN, CLIENT_ID_LEN + COOKIE_KEY_LEN)
        return AesCtr(cookieKey, entry.iv).process(entry.encryptedCookie)
    }

    /** Format an `auth-client` descriptor line. */
    fun authClientLine(entry: AuthClientEntry): String {
        val b64 = Base64.getEncoder().withoutPadding()
        return "auth-client " +
            b64.encodeToString(entry.clientId) + " " +
            b64.encodeToString(entry.iv) + " " +
            b64.encodeToString(entry.encryptedCookie)
    }

    @Deprecated("Use authClientLine(AuthClientEntry); CLIENT-ID depends on subcredential+ECDH")
    fun authClientLine(
        cred: ClientCred,
        encryptedCookie: ByteArray,
        iv: ByteArray = SecureRandomSource.nextBytes(IV_LEN),
    ): String {
        // Legacy helper: cannot compute real CLIENT-ID without subcred/ephemeral.
        val id = Base64.getEncoder().withoutPadding()
            .encodeToString(SecureRandomSource.nextBytes(CLIENT_ID_LEN))
        val ivB = Base64.getEncoder().withoutPadding().encodeToString(iv)
        val c = Base64.getEncoder().withoutPadding().encodeToString(encryptedCookie)
        return "auth-client $id $ivB $c"
    }

    fun parseAuthClients(firstLayerText: String): Pair<ByteArray?, List<AuthClientEntry>> {
        var ephemeral: ByteArray? = null
        val entries = mutableListOf<AuthClientEntry>()
        for (line in firstLayerText.lineSequence()) {
            when {
                line.startsWith("desc-auth-ephemeral-key ") -> {
                    ephemeral = parsePublicKeyB64(line.removePrefix("desc-auth-ephemeral-key ").trim())
                }
                line.startsWith("auth-client ") -> {
                    val parts = line.removePrefix("auth-client ").trim().split(Regex("\\s+"))
                    if (parts.size >= 3) {
                        entries += AuthClientEntry(
                            clientId = parsePublicKeyB64(parts[0]),
                            iv = parsePublicKeyB64(parts[1]),
                            encryptedCookie = parsePublicKeyB64(parts[2]),
                        )
                    }
                }
            }
        }
        return ephemeral to entries
    }

    fun parsePublicKeyB64(b64: String): ByteArray =
        Base64.getDecoder().decode(b64.padEnd((b64.length + 3) / 4 * 4, '='))
}
