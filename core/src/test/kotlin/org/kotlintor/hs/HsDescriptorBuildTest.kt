package org.kotlintor.hs

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.crypto.Curve25519
import org.kotlintor.crypto.Ed25519Keys
import java.time.Duration
import java.time.Instant

class HsDescriptorBuildTest {
    @Test
    fun `encrypt then decrypt round trip`() {
        val id = Ed25519Keys.generate()
        val period = HsTimePeriod.containing(
            Instant.parse("2024-06-15T15:00:00Z"),
            lengthMinutes = 1440,
            epochOffset = Duration.ofHours(12),
        )
        val auth = Ed25519Keys.generate()
        val enc = Curve25519.generateKeyPair()
        val links = byteArrayOf(
            3, // nspec
            0, 6, 1, 2, 3, 4, 0, 80, // ipv4:port
            2, 20, *ByteArray(20) { 0x11 }, // legacy id
            3, 32, *ByteArray(32) { 0x22 }, // ed25519
        )
        val doc = HsDescriptorCodec.build(
            HsDescriptorBuildInput(
                publicIdentity = id.publicKey,
                privateIdentitySeed = id.privateKey,
                period = period,
                revisionCounter = 42,
                introPoints = listOf(
                    IntroPointDescriptor(
                        linkSpecifiers = links,
                        onionKeyNtor = ByteArray(32) { 0x33 },
                        authPublic = auth.publicKey,
                        encKey = enc,
                    ),
                ),
            ),
        )
        assertTrue(doc.startsWith("hs-descriptor 3\n"))
        assertTrue(doc.contains("signature "))
        // C Tor includes the newline before "signature" in the signed region.
        assertTrue(doc.contains("-----END MESSAGE-----\nsignature "))

        val outer = HsDescriptorCodec.parseOuter(doc)
        assertEquals(42L, outer.revisionCounter)
        val blinded = HsKeyBlind.blindPublicKey(id.publicKey, period)
        val inner = HsDescriptorCodec.decrypt(outer, id.publicKey, blinded)
        assertEquals(listOf(2), inner.create2Formats)
        assertEquals(1, inner.introductionPoints.size)
        assertTrue(inner.introductionPoints[0].authKey.contentEquals(auth.publicKey))
        assertTrue(inner.introductionPoints[0].encKeyNtor.contentEquals(enc.publicKey))

        val sigLine = doc.lineSequence().first { it.startsWith("signature ") }
        val sigB64 = sigLine.removePrefix("signature ").trim()
        var padded = sigB64
        while (padded.length % 4 != 0) padded += "="
        val sig = java.util.Base64.getDecoder().decode(padded)
        // C Tor: signed region is bytes up through the '\n' before "signature ".
        val signedEnd = doc.indexOf("\nsignature ") + 1
        val prefix = "Tor onion service descriptor sig v3".toByteArray()
        val signingPub = Ed25519Cert.certifiedKeyFromPem(outer.signingKeyCertPem)
        assertTrue(
            org.kotlintor.crypto.Ed25519Keys.verify(
                signingPub,
                prefix + doc.substring(0, signedEnd).toByteArray(),
                sig,
            ),
        )
    }
}
