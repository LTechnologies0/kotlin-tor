package org.kotlintor.link

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test
import org.kotlintor.crypto.Ed25519Keys

class RsaEdCrossCertTest {
    @Test
    fun `encode verify round trip`() {
        val mat = OrCertMaterial.generate()
        val ed = Ed25519Keys.generate()
        val cert = RsaEdCrossCert.encode(ed.publicKey, mat.identityKey.private)
        assertArrayEquals(ed.publicKey, RsaEdCrossCert.verify(cert, mat.identityKey.public))
    }
}
