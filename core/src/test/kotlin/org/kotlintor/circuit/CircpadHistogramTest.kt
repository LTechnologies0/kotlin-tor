package org.kotlintor.circuit

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.circuit.Circpad.DELAY_INFINITE

class CircpadHistogramTest {
    @Test
    fun `sample depletes tokens and can hit infinity`() {
        val h = CircpadHistogram(
            tokens = intArrayOf(1, 0, 1),
            edgesUs = longArrayOf(0, 100, 200),
        )
        assertEquals(2, h.remainingTokens())
        val d1 = h.sampleDelayUs()
        assertTrue(d1 == DELAY_INFINITE || d1 < 200)
        h.sampleDelayUs()
        assertTrue(h.binsEmpty() || h.remainingTokens() == 0)
        assertEquals(DELAY_INFINITE, h.sampleDelayUs())
        h.refill()
        assertEquals(2, h.remainingTokens())
    }

    @Test
    fun `spec comment example constructs`() {
        val h = CircpadHistogram.exampleFromSpecComment()
        assertEquals(6, h.histogramLen)
        assertEquals(5, h.infinityBin)
        assertEquals(44, h.totalTokens)
    }
}
