package org.kotlintor.link

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.kotlintor.crypto.Ed25519Keys
import org.kotlintor.crypto.Digests
import org.kotlintor.hs.Ed25519Cert
import java.nio.file.Path

class OrCertMaterialTest {
    @Test
    fun `fingerprint matches CERTS parse`(@TempDir dir: Path) {
        val mat = OrCertMaterial.generate()
        mat.persist(dir)
        val loaded = OrCertMaterial.loadOrGenerate(dir)
        assertTrue(mat.identityFingerprint.contentEquals(loaded.identityFingerprint))
        val parsed = CertsCell.parse(loaded.certsCellPayload())
        assertEquals(2, parsed.certCount)
        assertTrue(loaded.identityFingerprint.contentEquals(parsed.rsaIdentityFingerprint))
    }

    @Test
    fun `CERTS includes Ed25519 identity and TLS digest certs`() {
        val mat = OrCertMaterial.generate()
        val id = Ed25519Keys.generate()
        val sign = Ed25519Keys.generate()
        val payload = mat.certsCellPayload(id, sign)
        val parsed = CertsCell.parse(payload)
        assertEquals(5, parsed.certCount)
        assertNotNull(parsed.ed25519Identity)
        assertTrue(id.publicKey.contentEquals(parsed.ed25519Identity!!))
        // Type-5 certifies SHA256(link X.509 DER)
        assertTrue(parsed.fingerprintsHex.any { it.startsWith("5:") })
        assertTrue(parsed.fingerprintsHex.any { it.startsWith("7:") })
        // Round-trip type-7 CrossCert
        val type7 = RsaEdCrossCert.encode(id.publicKey, mat.identityKey.private)
        assertTrue(RsaEdCrossCert.verify(type7, mat.identityKey.public).contentEquals(id.publicKey))
        val tlsDigest = Digests.sha256(mat.linkCert.encoded)
        // Re-encode type-5 independently and check certified key slot.
        val exp = InstantHours.nowPlus(24)
        val cert5 = Ed25519Cert.encode(
            certType = Ed25519Cert.TYPE_SIGNING_V_TLS_CERT,
            certifiedKey = tlsDigest,
            expirationHours = exp,
            signingKeySeed = sign.privateKey,
            certifiedKeyType = Ed25519Cert.KEY_TYPE_SHA256_OF_X509,
        )
        assertTrue(Ed25519Cert.certifiedKey(cert5).contentEquals(tlsDigest))
    }
}

private object InstantHours {
    fun nowPlus(hours: Long): Long =
        java.time.Instant.now().epochSecond / 3600 + hours
}
