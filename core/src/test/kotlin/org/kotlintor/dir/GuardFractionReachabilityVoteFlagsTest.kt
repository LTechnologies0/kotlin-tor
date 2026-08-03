package org.kotlintor.dir

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class GuardFractionReachabilityVoteFlagsTest {
    @Test
    fun `guardfraction parse and apply`() {
        val text = """
            guardfraction-file-version 1
            written-at 2020-01-01 00:00:00
            n-inputs 10 7
            guard-seen aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 55 3
            guard-seen bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 10 1
        """.trimIndent()
        val f = GuardFraction.parse(text)
        assertEquals(1, f.version)
        assertEquals(2, f.guards.size)
        val m = linkedMapOf("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" to 0)
        assertEquals(1, GuardFraction.applyTo(m, f, onlyKnown = true))
        assertEquals(55, m["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"])
    }

    @Test
    fun `reachability tls done and due buckets`() {
        val t = ReachabilityTracker(moduloPerTest = 1, testIntervalSec = 1)
        val target = ReachabilityTracker.Target(
            identityHex = "cc".repeat(20),
            ip = "1.2.3.4",
            orPort = 9001,
        )
        t.noteTarget(target)
        assertTrue(t.shouldLaunchTest(target, null))
        assertFalse(
            t.shouldLaunchTest(target, target.copy(ip = "1.2.3.4")),
        )
        assertTrue(t.shouldLaunchTest(target, target.copy(ip = "9.9.9.9")))
        val due = t.dueForTest(nowEpochSec = 100)
        assertEquals(1, due.size)
        assertTrue(t.noteTlsDone("cc".repeat(20), "1.2.3.4", 9001, nowEpochSec = 101))
        assertTrue(t.isReachable("cc".repeat(20)))
    }

    @Test
    fun `vote flags assign guard`() {
        val flags = VoteFlags.assign(
            VoteFlags.Input(
                bandwidthKb = 5_000,
                weightedBwKb = 5_000,
                uptimeSec = 8 * 24 * 3600,
                isExit = true,
                supportsHsDir = true,
            ),
        )
        assertTrue("Guard" in flags)
        assertTrue("Exit" in flags)
        assertTrue("HSDir" in flags)
        assertTrue("Fast" in flags)
        assertTrue("Stable" in flags)
    }

    @Test
    fun `conscache roundtrip`() {
        val c = ConsCache()
        val e = c.put("network-status-version 3\n")
        assertEquals(e, c.get(e.digestHex))
    }

    @Test
    fun `predict ports ranks`() {
        PredictPorts.clear()
        PredictPorts.noteUse(443)
        PredictPorts.noteUse(443)
        PredictPorts.noteUse(80)
        assertEquals(listOf(443, 80), PredictPorts.predicted(2))
    }
}
