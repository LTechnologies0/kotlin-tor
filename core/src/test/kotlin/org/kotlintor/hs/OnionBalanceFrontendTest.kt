package org.kotlintor.hs

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.crypto.Curve25519
import java.nio.file.Files
import java.time.Duration
import java.time.Instant

class OnionBalanceFrontendTest {
    @Test
    fun `frontend builds signed descriptor from backends`() {
        val fe = OnionBalanceFrontend.generate()
        fun ip(tag: Byte) = IntroPointDescriptor(
            linkSpecifiers = byteArrayOf(tag),
            onionKeyNtor = ByteArray(32) { tag },
            authPublic = ByteArray(32) { tag },
            encKey = Curve25519.generateKeyPair(),
        )
        fe.addBackend(OnionBalance.Backend("a", listOf(ip(1), ip(2))))
        fe.addBackend(OnionBalance.Backend("b", listOf(ip(3))))
        val period = HsTimePeriod.containing(
            Instant.parse("2024-06-15T15:00:00Z"),
            lengthMinutes = 1440,
            epochOffset = Duration.ofHours(12),
        )
        val doc = fe.buildDescriptor(period, revisionCounter = 1)
        assertTrue(doc.contains("hs-descriptor"))
        assertTrue(fe.address.endsWith(".onion"))
        val dir = Files.createTempDirectory("ob-fe")
        fe.saveKeys(dir)
        val loaded = OnionBalanceFrontend.load(dir)
        assertEquals(fe.address, loaded.address)
    }

    @Test
    fun `intro rate limit admits then rejects`() {
        val lim = HsIntroRateLimit(maxPerMinute = 3)
        assertTrue(lim.tryAdmit())
        assertTrue(lim.tryAdmit())
        assertTrue(lim.tryAdmit())
        assertEquals(false, lim.tryAdmit())
    }
}
