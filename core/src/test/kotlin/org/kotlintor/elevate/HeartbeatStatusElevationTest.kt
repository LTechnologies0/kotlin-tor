package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.kotlintor.status.HeartbeatStatus

/**
 * Elevates `L1:core/or/status.c` toward D3.
 *
 * Evidence: secs_to_uptime, bytes_to_usage, note_connection, log_heartbeat shape.
 */
class HeartbeatStatusElevationTest {
    @BeforeEach
    fun reset() {
        HeartbeatStatus.resetClock(1_000_000L)
    }

    @Test
    fun `secs_to_uptime formats days hours`() {
        assertEquals("0:05 hours", HeartbeatStatus.secsToUptime(5 * 60))
        assertEquals("1:02 hours", HeartbeatStatus.secsToUptime(3600 + 2 * 60))
        assertEquals("1 day 0:00 hours", HeartbeatStatus.secsToUptime(86400))
        assertEquals("2 days 3:04 hours", HeartbeatStatus.secsToUptime(2 * 86400 + 3 * 3600 + 4 * 60))
    }

    @Test
    fun `bytes_to_usage thresholds`() {
        assertEquals("1 kB", HeartbeatStatus.bytesToUsage(1024))
        assertTrue(HeartbeatStatus.bytesToUsage(2L * 1024 * 1024).endsWith("MB"))
        assertTrue(HeartbeatStatus.bytesToUsage(3L * 1024 * 1024 * 1024).endsWith("GB"))
    }

    @Test
    fun `note_connection and log_heartbeat`() {
        HeartbeatStatus.noteConnection(inbound = true, ipv6 = false)
        HeartbeatStatus.noteConnection(inbound = true, ipv6 = true)
        HeartbeatStatus.noteConnection(inbound = false, ipv6 = false)
        HeartbeatStatus.noteConnection(inbound = false, ipv6 = true)
        HeartbeatStatus.noteCircClosedForUnrecognizedCells(10, 3)
        val line = HeartbeatStatus.logHeartbeat(
            bytesRead = 2048,
            bytesWritten = 4096,
            circuitsOpen = 2,
            hibernating = true,
            inConsensus = false,
            nowMs = 1_000_000L + 90_000L,
        )
        assertTrue(line.contains("not in the cached consensus"))
        assertTrue(line.contains("0:01 hours"))
        assertTrue(line.contains("2 circuits open"))
        assertTrue(line.contains("hibernating"))
        assertTrue(line.contains("I've received 1 connections on IPv4 and 1 on IPv6"))
        assertTrue(line.contains("I've made 1 connections with IPv4 and 1 with IPv6"))
        assertTrue(line.contains("unrecognized cells"))
        assertEquals(intArrayOf(1, 1, 1, 1).toList(), HeartbeatStatus.connectionCounts().toList())
    }
}
