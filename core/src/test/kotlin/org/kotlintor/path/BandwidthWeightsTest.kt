package org.kotlintor.path

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.dir.RouterStatus
import java.time.Instant

class BandwidthWeightsTest {
    @Test
    fun `guard-only uses Wgg scaled bandwidth`() {
        val w = BandwidthWeights.fromParams(
            mapOf("bwweightscale" to 10_000L, "Wgg" to 5_000L, "Wmm" to 10_000L, "Wee" to 10_000L),
        )
        val guard = rs(flags = setOf("Guard", "Running", "Fast"), bw = 20_000)
        val wt = w.weight(guard, BandwidthWeights.Role.GUARD)
        assertEquals((20_000L * 5_000L) / 10_000L, wt)
        val middle = rs(flags = setOf("Running", "Fast"), bw = 10_000)
        assertTrue(w.weight(middle, BandwidthWeights.Role.MIDDLE) >= 1)
        val exit = rs(flags = setOf("Exit", "Running", "Fast"), bw = 10_000)
        assertTrue(w.weight(exit, BandwidthWeights.Role.EXIT) >= 1)
    }

    private fun rs(flags: Set<String>, bw: Long) = RouterStatus(
        nickname = "n",
        identity = ByteArray(20) { 1 },
        digest = ByteArray(20),
        publication = Instant.EPOCH,
        ip = "1.2.3.4",
        orPort = 9001,
        dirPort = 0,
        flags = flags,
        version = null,
        proto = emptyMap(),
        bandwidth = bw,
    )
}
