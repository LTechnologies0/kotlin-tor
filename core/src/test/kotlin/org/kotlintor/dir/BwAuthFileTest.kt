package org.kotlintor.dir

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BwAuthFileTest {
    @Test
    fun `parse headers and measured lines`() {
        val text = """
            timestamp=1000
            version=1.0.0
            =====
            node_id=${'$'}AABBCCDDEEFF00112233445566778899AABBCCDD bw=1500 nick=Foo
            node_id=${'$'}11223344556677889900AABBCCDDEEFF00112233 bw=2000
        """.trimIndent()
        val parsed = BwAuthFile.parse(text)
        assertEquals("1000", parsed.headers["timestamp"])
        assertEquals(2, parsed.lines.size)
        assertEquals("AABBCCDDEEFF00112233445566778899AABBCCDD", parsed.lines[0].nodeIdHex)
        assertEquals(1500L, parsed.lines[0].bwKb)
    }

    @Test
    fun `cache expires after MAX_MEASUREMENT_AGE`() {
        val cache = MeasuredBwCache()
        cache.put("AA", 100, asOfEpochSec = 1_000)
        assertEquals(100L, cache.get("AA", nowEpochSec = 1_000 + 100))
        assertNull(cache.get("AA", nowEpochSec = 1_000 + BwAuthFile.MAX_MEASUREMENT_AGE_SEC + 1))
    }

    @Test
    fun `DirCollator median with majority`() {
        val v1 = BandwidthVote.parse(
            BandwidthVote.formatMinimalVote("A", "ID1", 100) +
                BandwidthVote.formatMinimalVote("B", "ID2", 50).lines()
                    .filter { it.startsWith("r ") || it.startsWith("w ") || it.startsWith("s ") }
                    .joinToString("\n", prefix = "\n"),
        )
        // Simpler: two votes with overlapping ID1
        val a = BandwidthVote.parse(BandwidthVote.formatMinimalVote("Rel", "ID1", 100))
        val b = BandwidthVote.parse(
            BandwidthVote.formatMinimalVote("Rel", "ID1", 300).replace("Bandwidth=300", "Bandwidth=300 Measured=300"),
        )
        val c = BandwidthVote.parse(BandwidthVote.formatMinimalVote("Rel", "ID1", 200))
        val collated = DirCollator.collate(listOf(a, b, c), nAuthorities = 3)
        assertEquals(1, collated.size)
        assertEquals("ID1", collated[0].identity)
        // sorted 100,200,300 → median 200
        assertEquals(200L, collated[0].bandwidthKb)
        assertTrue(DirCollator.formatConsensusBody(collated).contains("Measured=200"))
    }
}
