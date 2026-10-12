package org.kotlintor.link

import org.kotlintor.crypto.Digests
import org.kotlintor.dir.TorCert
import org.kotlintor.hs.Ed25519Cert
import org.kotlintor.util.constantTimeEquals
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant

/**
 * CERTS cell validation (tor-spec link handshake):
 * - RSA type 1 (LINK) signed by type 2 (ID), both unexpired
 * - TLS peer certificate bound to type 1 (same encoded cert or public key)
 * - Ed25519 type 4 (IDENTITY_V_SIGNING) + type 5 (SIGNING_V_TLS_CERT) + type 7 RSA↔Ed crosscert
 */
object LinkCertsValidator {
    data class Validated(
        val rsaIdentityFingerprint: ByteArray,
        val ed25519Identity: ByteArray,
        val fingerprintsHex: List<String>,
    )

    data class TypedCert(val type: Int, val der: ByteArray)

    fun parseTyped(payload: ByteArray): List<TypedCert> {
        if (payload.isEmpty()) return emptyList()
        var o = 0
        val n = payload[o++].toInt() and 0xff
        val out = ArrayList<TypedCert>(n)
        repeat(n) {
            if (o + 3 > payload.size) return@repeat
            val certType = payload[o++].toInt() and 0xff
            val clen = ((payload[o].toInt() and 0xff) shl 8) or (payload[o + 1].toInt() and 0xff)
            o += 2
            if (o + clen > payload.size) return@repeat
            out += TypedCert(certType, payload.copyOfRange(o, o + clen))
            o += clen
        }
        return out
    }

    fun validate(payload: ByteArray, tlsPeer: X509Certificate?, now: Instant = Instant.now()): Validated {
        val certs = parseTyped(payload)
        require(certs.isNotEmpty()) { "CERTS: empty cell" }
        val cf = CertificateFactory.getInstance("X.509")
        val type1 = certs.firstOrNull { it.type == 1 } ?: error("CERTS: missing type-1 LINK X.509")
        val type2 = certs.firstOrNull { it.type == 2 } ?: error("CERTS: missing type-2 RSA identity X.509")
        val link = x509(cf, type1.der, "type-1")
        val id = x509(cf, type2.der, "type-2")
        checkExpiry(link, now, "type-1")
        checkExpiry(id, now, "type-2")
        try {
            link.verify(id.publicKey)
        } catch (e: Exception) {
            throw IllegalStateException("CERTS: type-1 not signed by type-2 identity", e)
        }
        if (tlsPeer != null) {
            val sameCert = constantTimeEquals(tlsPeer.encoded, link.encoded)
            val sameKey = constantTimeEquals(tlsPeer.publicKey.encoded, link.publicKey.encoded)
            if (!sameCert && !sameKey) {
                throw IllegalStateException("CERTS: type-1 does not bind TLS peer certificate")
            }
        }
        val rsaFp = CertsCell.rsaFingerprint(id)

        val type4 = certs.firstOrNull { it.type == 4 } ?: error("CERTS: missing type-4 Ed25519 identity→signing")
        val type5 = certs.firstOrNull { it.type == 5 } ?: error("CERTS: missing type-5 signing→TLS")
        val type7 = certs.firstOrNull { it.type == 7 } ?: error("CERTS: missing type-7 RSA↔Ed crosscert")

        val ed4 = TorCert.parse(type4.der) ?: error("CERTS: type-4 parse failed")
        require(ed4.certType == Ed25519Cert.TYPE_IDENTITY_V_SIGNING) { "CERTS: type-4 cert_type=${ed4.certType}" }
        checkEdExpiry(ed4.expirationHours, now, "type-4")
        val edId = ed4.signingKey ?: error("CERTS: type-4 missing signed-with-ed25519-key")
        if (TorCert.checksig(ed4, edId) != 0) error("CERTS: type-4 Ed25519 signature invalid")

        val ed5 = TorCert.parse(type5.der) ?: error("CERTS: type-5 parse failed")
        require(ed5.certType == Ed25519Cert.TYPE_SIGNING_V_TLS_CERT) { "CERTS: type-5 cert_type=${ed5.certType}" }
        checkEdExpiry(ed5.expirationHours, now, "type-5")
        if (TorCert.checksig(ed5, ed4.certifiedKey) != 0) error("CERTS: type-5 not signed by type-4 signing key")
        if (tlsPeer != null) {
            val tlsSha = Digests.sha256(tlsPeer.encoded)
            if (ed5.certifiedKeyType == Ed25519Cert.KEY_TYPE_SHA256_OF_X509) {
                if (!constantTimeEquals(ed5.certifiedKey, tlsSha)) {
                    throw IllegalStateException("CERTS: type-5 certified key is not SHA256(TLS peer)")
                }
            }
        }

        validateType7(type7.der, id, edId, now)

        val fps = listOf(
            "2:${rsaFp.joinToString("") { "%02x".format(it) }}",
            "4:ed25519:${edId.joinToString("") { "%02x".format(it) }}",
        )
        return Validated(rsaFp, edId, fps)
    }

    private fun validateType7(der: ByteArray, idCert: X509Certificate, edId: ByteArray, now: Instant) {
        require(der.size >= 36 + 64) { "CERTS: type-7 too short (${der.size})" }
        val claimedEd = der.copyOfRange(0, 32)
        if (!constantTimeEquals(claimedEd, edId)) {
            throw IllegalStateException("CERTS: type-7 Ed25519 identity does not match type-4")
        }
        val expHours = ((der[32].toLong() and 0xff) shl 24) or
            ((der[33].toLong() and 0xff) shl 16) or
            ((der[34].toLong() and 0xff) shl 8) or
            (der[35].toLong() and 0xff)
        checkEdExpiry(expHours, now, "type-7")
        try {
            RsaEdCrossCert.verify(der, idCert.publicKey)
        } catch (e: Exception) {
            throw IllegalStateException("CERTS: type-7 RSA crosscert invalid", e)
        }
    }

    private fun x509(cf: CertificateFactory, der: ByteArray, label: String): X509Certificate =
        try {
            cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        } catch (e: Exception) {
            throw IllegalStateException("CERTS: failed to parse $label X.509", e)
        }

    private fun checkExpiry(cert: X509Certificate, now: Instant, label: String) {
        val n = java.util.Date.from(now)
        if (n.before(cert.notBefore) || n.after(cert.notAfter)) {
            throw IllegalStateException("CERTS: $label expired or not yet valid (${cert.notBefore}–${cert.notAfter})")
        }
    }

    private fun checkEdExpiry(expirationHours: Long, now: Instant, label: String) {
        val exp = Instant.ofEpochSecond(expirationHours * 3600L)
        if (!now.isBefore(exp)) {
            throw IllegalStateException("CERTS: $label expired at $exp")
        }
    }
}
