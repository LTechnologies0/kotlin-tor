package org.kotlintor.dir

import org.kotlintor.crypto.Ed25519Keys
import org.kotlintor.hs.Ed25519Cert

/**
 * Tor certificate helpers (C Tor `torcert.c` → prop220 Ed25519 certs).
 *
 * Inventory: `L1:feature/nodelist/torcert.c`
 *
 * C Tor: `tor_cert_create_*`, `tor_cert_parse`, `tor_cert_checksig`,
 * `tor_cert_eq`, `tor_cert_describe_signature_status`.
 */
object TorCert {
    data class Parsed(
        val raw: ByteArray,
        val certType: Int,
        val expirationHours: Long,
        val certifiedKeyType: Int,
        val certifiedKey: ByteArray,
        val signingKey: ByteArray?,
        val signature: ByteArray,
        val body: ByteArray,
        var sigOk: Boolean? = null,
    )

    fun certifiedKeyFromPem(pem: String): ByteArray = Ed25519Cert.certifiedKeyFromPem(pem)

    fun certifiedKey(cert: ByteArray): ByteArray = Ed25519Cert.certifiedKey(cert)

    /** C Tor `tor_cert_create_ed25519` / encode path. */
    fun createEd25519(
        certType: Int,
        certifiedKey: ByteArray,
        expirationHours: Long,
        signingKeySeed: ByteArray,
        signedWithEd25519: ByteArray? = null,
        certifiedKeyType: Int = Ed25519Cert.KEY_TYPE_ED25519,
    ): ByteArray =
        encode(certType, certifiedKey, expirationHours, signingKeySeed, signedWithEd25519, certifiedKeyType)

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

    /** C Tor `tor_cert_parse` (prop220 layout). */
    fun parse(encoded: ByteArray): Parsed? {
        if (encoded.size < 7 + 32 + 64) return null
        if (encoded[0].toInt() and 0xff != 1) return null
        val certType = encoded[1].toInt() and 0xff
        val exp = ((encoded[2].toLong() and 0xff) shl 24) or
            ((encoded[3].toLong() and 0xff) shl 16) or
            ((encoded[4].toLong() and 0xff) shl 8) or
            (encoded[5].toLong() and 0xff)
        val keyType = encoded[6].toInt() and 0xff
        val certifiedKey = encoded.copyOfRange(7, 39)
        var off = 39
        val nExt = encoded[off].toInt() and 0xff
        off++
        var signingKey: ByteArray? = null
        repeat(nExt) {
            if (off + 4 > encoded.size - 64) return null
            val extLen = ((encoded[off].toInt() and 0xff) shl 8) or (encoded[off + 1].toInt() and 0xff)
            val extType = encoded[off + 2].toInt() and 0xff
            // flags at off+3
            val dataStart = off + 4
            val dataEnd = dataStart + extLen
            if (dataEnd > encoded.size - 64) return null
            if (extType == Ed25519Cert.EXT_SIGNED_WITH_ED25519 && extLen == 32) {
                signingKey = encoded.copyOfRange(dataStart, dataEnd)
            }
            off = dataEnd
        }
        if (off + 64 > encoded.size) return null
        val body = encoded.copyOfRange(0, off)
        val signature = encoded.copyOfRange(off, off + 64)
        return Parsed(
            raw = encoded.copyOf(off + 64),
            certType = certType,
            expirationHours = exp,
            certifiedKeyType = keyType,
            certifiedKey = certifiedKey,
            signingKey = signingKey,
            signature = signature,
            body = body,
        )
    }

    /**
     * C Tor `tor_cert_checksig` — verify with [signingPublic] (or embedded EXT key).
     * @return 0 on success, -1 on failure
     */
    fun checksig(parsed: Parsed, signingPublic: ByteArray? = null): Int {
        val pub = signingPublic ?: parsed.signingKey ?: return -1
        if (pub.size != 32 || parsed.signature.size != 64) return -1
        val ok = Ed25519Keys.verify(pub, parsed.body, parsed.signature)
        parsed.sigOk = ok
        return if (ok) 0 else -1
    }

    /** C Tor `tor_cert_describe_signature_status`. */
    fun describeSignatureStatus(parsed: Parsed): String = when (parsed.sigOk) {
        true -> "validated"
        false -> "invalid"
        null -> "unchecked"
    }

    /** C Tor `tor_cert_eq`. */
    fun eq(a: ByteArray, b: ByteArray): Boolean = a.contentEquals(b)

    fun eq(a: Parsed, b: Parsed): Boolean = a.raw.contentEquals(b.raw)

    /** Verify certified-key extraction succeeds and length is 32. */
    fun looksValid(cert: ByteArray): Boolean =
        runCatching { certifiedKey(cert).size == 32 }.getOrDefault(false)

    const val TYPE_IDENTITY_V_SIGNING: Int = Ed25519Cert.TYPE_IDENTITY_V_SIGNING
    const val TYPE_SIGNING_V_TLS_CERT: Int = Ed25519Cert.TYPE_SIGNING_V_TLS_CERT
    const val TYPE_BLINDED_ID_V_SIGNING: Int = Ed25519Cert.TYPE_BLINDED_ID_V_SIGNING
    const val TYPE_HS_IP_V_SIGNING: Int = Ed25519Cert.TYPE_HS_IP_V_SIGNING
    const val TYPE_HS_IP_CC_SIGNING: Int = Ed25519Cert.TYPE_HS_IP_CC_SIGNING
}
