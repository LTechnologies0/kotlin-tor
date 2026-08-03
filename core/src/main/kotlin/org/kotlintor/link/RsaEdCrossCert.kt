package org.kotlintor.link

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.PrivateKey
import java.security.Security
import java.security.Signature
import java.time.Instant

/**
 * CERTS cell type 7 — RSA→Ed25519 cross-certificate (cert-spec).
 *
 * ```
 * ED25519_KEY   [32]
 * EXPIRATION    [4]   // hours since epoch
 * SIGNATURE     [keysize]  // RSA-SHA256 of PREFIX‖FIELDS
 * ```
 * PREFIX = `Tor TLS RSA/Ed25519 cross-certificate`
 */
object RsaEdCrossCert {
    private const val PREFIX = "Tor TLS RSA/Ed25519 cross-certificate"
    const val CERTS_TYPE: Int = 7

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    fun encode(ed25519Identity: ByteArray, rsaIdentityPrivate: PrivateKey, expirationHours: Long = defaultExpirationHours()): ByteArray {
        require(ed25519Identity.size == 32)
        val fields = ed25519Identity + u32be(expirationHours)
        val sig = Signature.getInstance("SHA256withRSA")
        sig.initSign(rsaIdentityPrivate)
        sig.update(PREFIX.toByteArray(Charsets.US_ASCII))
        sig.update(fields)
        return fields + sig.sign()
    }

    fun verify(cert: ByteArray, rsaIdentityPublic: java.security.PublicKey): ByteArray {
        require(cert.size > 36) { "cross-cert too short" }
        val ed = cert.copyOfRange(0, 32)
        val fields = cert.copyOfRange(0, 36)
        val signature = cert.copyOfRange(36, cert.size)
        val sig = Signature.getInstance("SHA256withRSA")
        sig.initVerify(rsaIdentityPublic)
        sig.update(PREFIX.toByteArray(Charsets.US_ASCII))
        sig.update(fields)
        check(sig.verify(signature)) { "RSA↔Ed cross-cert signature invalid" }
        return ed
    }

    fun defaultExpirationHours(): Long = Instant.now().epochSecond / 3600 + 24L * 60

    private fun u32be(v: Long): ByteArray =
        byteArrayOf(
            ((v ushr 24) and 0xff).toByte(),
            ((v ushr 16) and 0xff).toByte(),
            ((v ushr 8) and 0xff).toByte(),
            (v and 0xff).toByte(),
        )
}
