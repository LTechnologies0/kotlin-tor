package org.kotlintor.hs

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.crypto.Ed25519Keys
import org.kotlintor.util.SecureRandomSource
import java.time.Duration
import java.time.Instant

class HsClientAuthRoundTripTest {
    @Test
    fun `seal open cookie shake aes ctr`() {
        val client = HsClientAuth.generate("bob")
        val eph = org.kotlintor.crypto.Curve25519.generateKeyPair()
        val subcred = SecureRandomSource.nextBytes(32)
        val (cookie, entry) = HsClientAuth.sealCookie(subcred, eph.privateKey, client.publicKey)
        val opened = HsClientAuth.openCookie(subcred, client.privateKey, eph.publicKey, entry)
        assertNotNull(opened)
        assertArrayEquals(cookie, opened)
        val wrong = HsClientAuth.openCookie(
            SecureRandomSource.nextBytes(32),
            client.privateKey,
            eph.publicKey,
            entry,
        )
        assertNull(wrong)
    }

    @Test
    fun `descriptor client-auth encrypt decrypt`() {
        val id = Ed25519Keys.generate()
        val client = HsClientAuth.generate("alice")
        val period = HsTimePeriod.containing(
            Instant.parse("2024-06-15T15:00:00Z"),
            lengthMinutes = 1440,
            epochOffset = Duration.ofHours(12),
        )
        val blinded = HsKeyBlind.blindPublicKey(id.publicKey, period)
        val doc = HsDescriptorCodec.build(
            HsDescriptorBuildInput(
                publicIdentity = id.publicKey,
                privateIdentitySeed = id.privateKey,
                period = period,
                revisionCounter = 42,
                introPoints = emptyList(),
                authorizedClients = listOf(client),
            ),
        )
        val outer = HsDescriptorCodec.parseOuter(doc)
        val inner = HsDescriptorCodec.decryptWithClientAuth(outer, id.publicKey, blinded, client)
        assertTrue(inner.raw.contains("create2-formats"))
    }
}
