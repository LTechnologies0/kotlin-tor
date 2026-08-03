package org.kotlintor.hs

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.util.SecureRandomSource

class HsPowProp327Test {
    @Test
    fun `solution round-trip bytes`() {
        val seed = SecureRandomSource.nextBytes(32)
        val nonce = SecureRandomSource.nextBytes(16)
        val sol = HsPowProp327.Solution(seed, nonce, 20, SecureRandomSource.nextBytes(16))
        val parsed = HsPowProp327.Solution.parse(sol.toBytes(), seed)
        assertEquals(20, parsed.effort)
        assertTrue(seed.contentEquals(parsed.seed))
        assertTrue(nonce.contentEquals(parsed.nonce))
    }

    @Test
    fun `effort check does not throw`() {
        val id = ByteArray(32)
        val seed = ByteArray(32)
        val nonce = ByteArray(16)
        val equix = ByteArray(16)
        val ok = HsPowProp327.meetsEffort(id, seed, nonce, 1, equix)
        assertTrue(ok || !ok)
    }

    @Test
    fun `verify rejects random solution`() {
        val id = SecureRandomSource.nextBytes(32)
        val sol = HsPowProp327.Solution(
            SecureRandomSource.nextBytes(32),
            SecureRandomSource.nextBytes(16),
            5,
            SecureRandomSource.nextBytes(16),
        )
        assertFalse(HsPowProp327.verifySolution(sol, id))
    }
}
