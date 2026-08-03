package org.kotlintor.dir

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BandwidthVoteTest {
    @Test
    fun `parse vote w lines`() {
        val doc = BandwidthVote.formatMinimalVote("TestRelay", "AAAA", 1500)
        val parsed = BandwidthVote.parse(doc)
        assertEquals("vote", parsed.header.voteStatus)
        assertEquals(3, parsed.header.networkStatusVersion)
        assertEquals(1, parsed.routers.size)
        assertEquals("TestRelay", parsed.routers[0].nickname)
        assertEquals(1500L, parsed.routers[0].bandwidth)
        assertTrue(BandwidthVote.formatWLine(100, measured = 90).contains("Measured=90"))
    }

    @Test
    fun `bandwidth probe estimates kbps`() = runBlocking {
        val payload = ByteArray(64 * 1024) { 1 }
        var offset = 0
        val result = BandwidthProbe.measure(
            read = { dst ->
                if (offset >= payload.size) return@measure -1
                val n = minOf(dst.size, payload.size - offset)
                System.arraycopy(payload, offset, dst, 0, n)
                offset += n
                n
            },
            bytes = payload.size.toLong(),
        )
        assertEquals(payload.size.toLong(), result.bytes)
        assertTrue(result.bandwidthKbPerSec >= 1)
    }
}
