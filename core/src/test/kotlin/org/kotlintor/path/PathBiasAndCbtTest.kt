package org.kotlintor.path

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PathBiasAndCbtTest {
    @Test
    fun `path bias state transitions`() {
        val t = PathBiasTracker(minCircs = 2)
        t.markBuildAttempted(1, "aa")
        t.markBuildSucceeded(1, "aa")
        t.markUseAttempted(1, "aa")
        t.markUseSucceeded(1, "aa")
        assertEquals(PathState.USE_SUCCEEDED, t.state(1))
        assertEquals(1, t.counters("aa").useSucceeded)
        // Force extreme
        repeat(5) {
            t.markBuildAttempted(10L + it, "bb")
        }
        assertEquals(PathBiasTracker.Level.EXTREME, t.assess("bb"))
    }

    @Test
    fun `cbt quantile`() {
        val cbt = CircuitBuildTimeout(minSamples = 5, quantile = 0.8)
        listOf(1000L, 2000L, 3000L, 4000L, 5000L).forEach { cbt.addSuccess(it) }
        val t = cbt.timeoutMs()
        assertTrue(t in 4000..5000)
    }
}
