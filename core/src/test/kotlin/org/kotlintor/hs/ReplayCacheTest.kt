package org.kotlintor.hs

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ReplayCacheTest {
    @Test
    fun `first insert is not replay second is`() {
        val c = ReplayCache(horizonSec = 300, scrubIntervalSec = 0)
        val blob = ByteArray(64) { it.toByte() }
        assertFalse(c.addAndTest(blob, nowEpochSec = 1_000))
        assertTrue(c.addAndTest(blob, nowEpochSec = 1_010))
        assertEquals(1, c.size)
    }

    @Test
    fun `aged out entry is not replay`() {
        val c = ReplayCache(horizonSec = 60, scrubIntervalSec = 0)
        val blob = "encrypted-section".toByteArray()
        assertFalse(c.addAndTest(blob, nowEpochSec = 100))
        // Past horizon → treated as new
        assertFalse(c.addAndTest(blob, nowEpochSec = 200))
    }
}
