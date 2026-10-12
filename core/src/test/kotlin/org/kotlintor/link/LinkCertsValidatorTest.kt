package org.kotlintor.link

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.crypto.Ed25519Keys

class LinkCertsValidatorTest {
    @Test
    fun `empty CERTS cell is rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            LinkCertsValidator.validate(ByteArray(0), tlsPeer = null)
        }
    }

    @Test
    fun `RSA-only CERTS missing Ed25519 types fails`() {
        val mat = OrCertMaterial.generate()
        val payload = mat.certsCellPayload()
        val ex = assertThrows(IllegalStateException::class.java) {
            LinkCertsValidator.validate(payload, tlsPeer = mat.linkCert)
        }
        assertTrue(ex.message!!.contains("type-4"), ex.message)
    }

    @Test
    fun `generated CERTS cell validates against link X509`() {
        val mat = OrCertMaterial.generate()
        val id = Ed25519Keys.generate()
        val sign = Ed25519Keys.generate()
        val payload = mat.certsCellPayload(id, sign)
        val v = LinkCertsValidator.validate(payload, tlsPeer = mat.linkCert)
        assertArrayEquals(mat.identityFingerprint, v.rsaIdentityFingerprint)
        assertArrayEquals(id.publicKey, v.ed25519Identity)
    }

    @Test
    fun `type-1 TLS bind mismatch fails`() {
        val mat = OrCertMaterial.generate()
        val other = OrCertMaterial.generate()
        val id = Ed25519Keys.generate()
        val sign = Ed25519Keys.generate()
        val payload = mat.certsCellPayload(id, sign)
        val ex = assertThrows(IllegalStateException::class.java) {
            LinkCertsValidator.validate(payload, tlsPeer = other.linkCert)
        }
        assertTrue(ex.message!!.contains("TLS"), ex.message)
    }
}
