package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.dir.Keypin

/**
 * Elevates `L1:feature/dirauth/keypin.c` toward D3.
 *
 * Evidence: KEYPIN_FOUND/ADDED/MISMATCH/NOT_FOUND, lone RSA, journal append.
 */
class KeypinElevationTest {
    private fun rsa(n: Byte = 1) = ByteArray(20) { n }
    private fun ed(n: Byte = 2) = ByteArray(32) { n }

    @Test
    fun `check_and_add FOUND ADDED MISMATCH`() {
        val j = Keypin.Journal()
        assertEquals(Keypin.Result.NOT_FOUND, j.check(rsa(1), ed(1)))
        assertEquals(Keypin.Result.ADDED, j.checkAndAdd(rsa(1), ed(1)))
        assertEquals(Keypin.Result.FOUND, j.check(rsa(1), ed(1)))
        assertEquals(Keypin.Result.FOUND, j.checkAndAdd(rsa(1), ed(1)))
        assertEquals(Keypin.Result.MISMATCH, j.checkAndAdd(rsa(1), ed(9)))
        assertEquals(Keypin.Result.MISMATCH, j.check(rsa(2), ed(1)))
        assertEquals(Keypin.Result.REPLACED, j.checkAndAdd(rsa(1), ed(9), replace = true))
        assertEquals(Keypin.Result.FOUND, j.check(rsa(1), ed(9)))
        assertTrue(j.pendingJournalLines().isNotEmpty())
    }

    @Test
    fun `check_lone_rsa and verifyAll`() {
        val j = Keypin.Journal()
        assertEquals(Keypin.Result.NOT_FOUND, j.checkLoneRsaStatus(rsa(1)))
        assertTrue(j.checkLoneRsa(rsa(1)))
        j.checkAndAdd(rsa(1), ed(1))
        assertEquals(Keypin.Result.MISMATCH, j.checkLoneRsaStatus(rsa(1)))
        assertFalse(j.checkLoneRsa(rsa(1)))
        assertTrue(j.verifyAll())
        assertEquals(Keypin.Result.OK, Keypin.Result.FOUND)
        assertEquals(Keypin.Result.CONFLICT, Keypin.Result.MISMATCH)
    }

    @Test
    fun `journal roundtrip`() {
        val j = Keypin.Journal()
        j.checkAndAdd(rsa(3), ed(3))
        val text = j.formatJournal()
        val j2 = Keypin.Journal()
        j2.loadJournal(text)
        assertEquals(Keypin.Result.FOUND, j2.check(rsa(3), ed(3)))
        assertEquals(1, j2.size())
    }
}
