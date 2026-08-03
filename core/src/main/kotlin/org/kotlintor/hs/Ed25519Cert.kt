package org.kotlintor.hs

import org.kotlintor.crypto.Ed25519Blind
import org.kotlintor.crypto.Ed25519Keys
import org.kotlintor.util.concat
import org.kotlintor.util.u16be
import org.kotlintor.util.u32be
import java.util.Base64

/** prop220 Ed25519 certificates (cert-spec). */
object Ed25519Cert {
    const val TYPE_IDENTITY_V_SIGNING: Int = 0x04
    const val TYPE_SIGNING_V_TLS_CERT: Int = 0x05
    const val TYPE_BLINDED_ID_V_SIGNING: Int = 0x08
    const val TYPE_HS_IP_V_SIGNING: Int = 0x09
    const val TYPE_HS_IP_CC_SIGNING: Int = 0x0B
    const val EXT_SIGNED_WITH_ED25519: Int = 0x04
    const val KEY_TYPE_ED25519: Int = 0x01
    const val KEY_TYPE_SHA256_OF_X509: Int = 0x03

    fun certifiedKeyFromPem(pem: String): ByteArray {
        val b64 = pem.lineSequence()
            .filter { !it.contains("BEGIN") && !it.contains("END") && it.isNotBlank() }
            .joinToString("")
            .replace("\\s".toRegex(), "")
        var padded = b64
        while (padded.length % 4 != 0) padded += "="
        return certifiedKey(Base64.getDecoder().decode(padded))
    }

    fun certifiedKey(cert: ByteArray): ByteArray {
        require(cert.size >= 7 + 32) { "ed25519 cert too short: ${cert.size}" }
        require(cert[0].toInt() and 0xff == 1) { "unsupported cert version ${cert[0]}" }
        // VERSION(1) CERT_TYPE(1) EXPIRATION(4) CERT_KEY_TYPE(1) CERTIFIED_KEY(32)
        return cert.copyOfRange(7, 39)
    }

    /**
     * Encode a prop220 Ed25519 certificate.
     * [signingKeySeed] is a 32-byte Ed25519 seed, or null when [signingExpanded] is used.
     */
    fun encode(
        certType: Int,
        certifiedKey: ByteArray,
        expirationHours: Long,
        signingKeySeed: ByteArray? = null,
        signingExpanded: Ed25519Blind.ExpandedSecret? = null,
        signedWithEd25519: ByteArray? = null,
        certifiedKeyType: Int = KEY_TYPE_ED25519,
    ): ByteArray {
        require(certifiedKey.size == 32)
        require((signingKeySeed != null) xor (signingExpanded != null)) {
            "provide exactly one of signingKeySeed or signingExpanded"
        }
        val prefix = concat(
            byteArrayOf(0x01, certType.toByte()),
            u32be(expirationHours),
            byteArrayOf(certifiedKeyType.toByte()),
            certifiedKey,
        )
        val extensions = if (signedWithEd25519 != null) {
            require(signedWithEd25519.size == 32)
            concat(
                byteArrayOf(1), // N_EXTENSIONS
                u16be(32), // ExtLen
                byteArrayOf(EXT_SIGNED_WITH_ED25519.toByte(), 0), // type, flags
                signedWithEd25519,
            )
        } else {
            byteArrayOf(0)
        }
        val body = concat(prefix, extensions)
        val sig = when {
            signingExpanded != null -> Ed25519Blind.signExpanded(signingExpanded, body)
            else -> Ed25519Keys.sign(signingKeySeed!!, body)
        }
        return concat(body, sig)
    }

    fun toPem(cert: ByteArray): String {
        val b64 = Base64.getEncoder().encodeToString(cert)
        val lines = b64.chunked(64).joinToString("\n")
        return "-----BEGIN ED25519 CERT-----\n$lines\n-----END ED25519 CERT-----"
    }
}
