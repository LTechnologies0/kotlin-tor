package org.kotlintor.hs

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class HsPowTest {
    @Test
    fun `hashcash solve verify low effort`() {
        val ch = HsPow.challenge(effort = 10)
        val sol = HsPow.solve(ch, maxAttempts = 10_000_000)
        assertNotNull(sol)
        assertTrue(HsPow.verify(sol!!))
        assertFalse(HsPow.meetsEffort(sol.seed, ByteArray(16) { 0xA5.toByte() }, sol.effort) &&
            sol.nonce.contentEquals(ByteArray(16) { 0xA5.toByte() }))
        // Mutate seed so verify fails
        assertFalse(HsPow.verify(sol.copy(seed = ByteArray(32) { 1 })))
    }
}
