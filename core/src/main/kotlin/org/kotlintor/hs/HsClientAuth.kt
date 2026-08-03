package org.kotlintor.hs

import org.kotlintor.crypto.Curve25519
import org.kotlintor.crypto.Digests
import org.kotlintor.util.SecureRandomSource
import org.kotlintor.util.concat
import java.util.Base64

/**
 * Onion service client authorization (x25519) — rend-spec HS client-auth lite.
 *
 * Host embeds auth-client entries; authorized clients ECDH with desc-auth-ephemeral-key
 * to recover the descriptor cookie used as the second-layer secret.
 */
object HsClientAuth {
    data class ClientCred(
        val name: String,
        val privateKey: ByteArray,
        val publicKey: ByteArray,
    )

    data class AuthClientEntry(
        val clientId: ByteArray,
        val iv: ByteArray,
        val encryptedCookie: ByteArray,
    )

    fun generate(name: String = "client"): ClientCred {
        val kp = Curve25519.generateKeyPair()
        return ClientCred(name, kp.privateKey, kp.publicKey)
    }

    fun clientId(publicKey: ByteArray): ByteArray =
        Digests.sha256(publicKey).copyOf(8)

    /**
     * Encrypt descriptor [cookie] for [clientPub] using [ephemeralPriv] (host side).
     * ciphertext = cookie XOR SHA256(shared ‖ "descriptor-cookie")[0..15]
     */
    fun sealCookie(
        ephemeralPriv: ByteArray,
        clientPub: ByteArray,
        cookie: ByteArray = SecureRandomSource.nextBytes(16),
    ): Pair<ByteArray, ByteArray> {
        require(cookie.size == 16)
        val shared = Curve25519.sharedSecret(ephemeralPriv, clientPub)
        val mask = Digests.sha256(concat(shared, "descriptor-cookie".toByteArray())).copyOf(16)
        val enc = ByteArray(16) { i -> (cookie[i].toInt() xor mask[i].toInt()).toByte() }
        return cookie to enc
    }

    /** Client recovers cookie from sealed entry + ephemeral public. */
    fun openCookie(
        clientPriv: ByteArray,
        ephemeralPub: ByteArray,
        encryptedCookie: ByteArray,
    ): ByteArray {
        require(encryptedCookie.size == 16)
        val shared = Curve25519.sharedSecret(clientPriv, ephemeralPub)
        val mask = Digests.sha256(concat(shared, "descriptor-cookie".toByteArray())).copyOf(16)
        return ByteArray(16) { i -> (encryptedCookie[i].toInt() xor mask[i].toInt()).toByte() }
    }

    fun authClientLine(cred: ClientCred, encryptedCookie: ByteArray, iv: ByteArray = SecureRandomSource.nextBytes(16)): String {
        val id = Base64.getEncoder().withoutPadding().encodeToString(clientId(cred.publicKey))
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
