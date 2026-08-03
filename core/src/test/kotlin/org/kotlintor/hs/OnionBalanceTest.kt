package org.kotlintor.hs

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.crypto.Curve25519

class OnionBalanceTest {
    @Test
    fun `merge intros round-robin dedupe`() {
        fun ip(tag: Byte): IntroPointDescriptor {
            val enc = Curve25519.generateKeyPair()
            return IntroPointDescriptor(
                linkSpecifiers = byteArrayOf(tag),
                onionKeyNtor = ByteArray(32) { tag },
                authPublic = ByteArray(32) { tag },
                encKey = enc,
            )
        }
        val a = OnionBalance.Backend("a", listOf(ip(1), ip(2)))
        val b = OnionBalance.Backend("b", listOf(ip(1), ip(3))) // auth 1 dup with a
        val merged = OnionBalance.mergeIntroPoints(listOf(a, b), maxIntros = 10)
        assertEquals(3, merged.size)
        val tags = merged.map { it.linkSpecifiers[0] }.toSet()
        assertTrue(tags.containsAll(listOf(1.toByte(), 2.toByte(), 3.toByte())))
        assertEquals(3, merged.map { it.authPublic[0] }.toSet().size)
    }
}
