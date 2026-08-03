package org.kotlintor.dir

import org.kotlintor.hs.Ed25519Cert

/**
 * Tor certificate helpers (C Tor `torcert.c` → prop220 Ed25519 certs).
 *
 * Inventory: `L1:feature/nodelist/torcert.c`
 */
object TorCert {
    fun certifiedKeyFromPem(pem: String): ByteArray = Ed25519Cert.certifiedKeyFromPem(pem)

    fun certifiedKey(cert: ByteArray): ByteArray = Ed25519Cert.certifiedKey(cert)

    fun encode(
        certType: Int,
        certifiedKey: ByteArray,
        expirationHours: Long,
        signingKeySeed: ByteArray,
        signedWithEd25519: ByteArray? = null,
        certifiedKeyType: Int = Ed25519Cert.KEY_TYPE_ED25519,
    ): ByteArray =
        Ed25519Cert.encode(
            certType = certType,
            certifiedKey = certifiedKey,
            expirationHours = expirationHours,
            signingKeySeed = signingKeySeed,
            signedWithEd25519 = signedWithEd25519,
            certifiedKeyType = certifiedKeyType,
        )

    fun toPem(cert: ByteArray): String = Ed25519Cert.toPem(cert)

    /** Verify certified-key extraction succeeds and length is 32. */
    fun looksValid(cert: ByteArray): Boolean =
        runCatching { certifiedKey(cert).size == 32 }.getOrDefault(false)

    const val TYPE_IDENTITY_V_SIGNING: Int = Ed25519Cert.TYPE_IDENTITY_V_SIGNING
    const val TYPE_SIGNING_V_TLS_CERT: Int = Ed25519Cert.TYPE_SIGNING_V_TLS_CERT
    const val TYPE_BLINDED_ID_V_SIGNING: Int = Ed25519Cert.TYPE_BLINDED_ID_V_SIGNING
    const val TYPE_HS_IP_V_SIGNING: Int = Ed25519Cert.TYPE_HS_IP_V_SIGNING
    const val TYPE_HS_IP_CC_SIGNING: Int = Ed25519Cert.TYPE_HS_IP_CC_SIGNING
}
