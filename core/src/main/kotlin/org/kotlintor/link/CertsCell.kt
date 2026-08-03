package org.kotlintor.link

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.kotlintor.crypto.Digests
import org.kotlintor.util.toHex
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Parse CERTS cell. Tor RSA fingerprint = SHA1(DER PKCS#1 RSAPublicKey),
 * not SHA1(X.509 SubjectPublicKeyInfo). Ed25519 identity from type-4
 * signed-with-ed25519-key extension when present.
 */
object CertsCell {
    data class Parsed(
        val certCount: Int,
        val rsaIdentityFingerprint: ByteArray?,
        val ed25519Identity: ByteArray? = null,
        val fingerprintsHex: List<String>,
    )

    fun parse(payload: ByteArray): Parsed {
        if (payload.isEmpty()) return Parsed(0, null, null, emptyList())
        var o = 0
        val n = payload[o++].toInt() and 0xff
        val fps = mutableListOf<String>()
        var rsaId: ByteArray? = null
        var edId: ByteArray? = null
        val cf = CertificateFactory.getInstance("X.509")
        repeat(n) {
            if (o + 3 > payload.size) return@repeat
            val certType = payload[o++].toInt() and 0xff
            val clen = ((payload[o].toInt() and 0xff) shl 8) or (payload[o + 1].toInt() and 0xff)
            o += 2
            if (o + clen > payload.size) return@repeat
            val der = payload.copyOfRange(o, o + clen)
            o += clen
            // 2 = RSA_ID_X509 legacy identity certificate
            // 1 = LINK_X509 (also RSA, signed by identity)
            if (certType == 2 || certType == 1) {
                runCatching {
                    val cert = cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
                    val fp = rsaFingerprint(cert)
                    fps += "${certType}:${fp.toHex()}"
                    if (certType == 2) rsaId = fp
                    if (rsaId == null && certType == 1) rsaId = fp
                }
            }
            // 4 = IDENTITY_V_SIGNING — extract KP_relayid_ed from signed-with extension
            if (certType == 4 && der.size >= 42) {
                runCatching {
                    // VERSION CERT_TYPE EXPIRATION CERT_KEY_TYPE CERTIFIED_KEY N_EXTENSIONS ...
                    var i = 7 + 32 // after certified key
                    val nExt = der[i++].toInt() and 0xff
                    repeat(nExt) {
                        if (i + 4 > der.size) return@repeat
                        val extLen = ((der[i].toInt() and 0xff) shl 8) or (der[i + 1].toInt() and 0xff)
                        val extType = der[i + 2].toInt() and 0xff
                        i += 4
                        if (i + extLen > der.size) return@repeat
                        if (extType == 0x04 && extLen == 32) {
                            edId = der.copyOfRange(i, i + 32)
                            fps += "4:ed25519:${edId!!.toHex()}"
                        }
                        i += extLen
                    }
                }
            }
            if (certType == 5) {
                fps += "5:signing-v-tls-cert(${der.size})"
            }
            if (certType == 7 && der.size >= 36) {
                val ed = der.copyOfRange(0, 32)
                fps += "7:rsa-id-v-identity:${ed.toHex()}"
                if (edId == null) edId = ed
            }
        }
        return Parsed(n, rsaId, edId, fps)
    }

    /** SHA1 of PKCS#1 RSAPublicKey DER (Tor identity fingerprint). */
    fun rsaFingerprint(cert: X509Certificate): ByteArray {
        val spki = SubjectPublicKeyInfo.getInstance(cert.publicKey.encoded)
        val pkcs1 = spki.publicKeyData.bytes
        return Digests.sha1(pkcs1)
    }

    /** SHA256 of PKCS#1 RSAPublicKey DER (AUTH0003 CID/SID). */
    fun rsaIdentitySha256(cert: X509Certificate): ByteArray {
        val spki = SubjectPublicKeyInfo.getInstance(cert.publicKey.encoded)
        return Digests.sha256(spki.publicKeyData.bytes)
    }

    /** Extract RSA_ID_X509 (type 2) SHA256 for AUTHENTICATE SID/CID. */
    fun rsaIdentitySha256FromCertsPayload(payload: ByteArray): ByteArray? {
        if (payload.isEmpty()) return null
        var o = 0
        val n = payload[o++].toInt() and 0xff
        val cf = CertificateFactory.getInstance("X.509")
        repeat(n) {
            if (o + 3 > payload.size) return@repeat
            val certType = payload[o++].toInt() and 0xff
            val clen = ((payload[o].toInt() and 0xff) shl 8) or (payload[o + 1].toInt() and 0xff)
            o += 2
            if (o + clen > payload.size) return@repeat
            val der = payload.copyOfRange(o, o + clen)
            o += clen
            if (certType == 2) {
                return runCatching {
                    val cert = cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
                    rsaIdentitySha256(cert)
                }.getOrNull()
            }
        }
        return null
    }
}
