package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.config.TorrcParser
import java.nio.file.Files

/**
 * Elevates remaining L4 D1 ack-only options into typed TorConfig/runtime fields.
 * Inventory: PathBias*, ServerDNS*, GroupReadable*, MaxMemInQueues_*, HS SingleHop/NonAnonymous.
 */
class L4TypedOptionsElevationTest {
    @Test
    fun `pathbias serverdns groupreadable maxmem parse`() {
        val dir = Files.createTempDirectory("ktor-l4")
        val torrc = dir.resolve("torrc")
        Files.writeString(
            torrc,
            """
            DataDirectory $dir
            PathBiasCircThreshold 50
            PathBiasNoticeRate 0.5
            ServerDNSAllowBrokenConfig 1
            ServerDNSRandomizeCase 0
            DataDirectoryGroupReadable 1
            KeyDirectoryGroupReadable 1
            MaxMemInQueues 64 MB
            MaxMemInQueuesLowThreshold 32 MB
            AddressDisableIPv6 1
            LogTimeGranularity 10
            ConnLimit 500
            HiddenServiceDir ${dir.resolve("hs")}
            HiddenServicePort 80 127.0.0.1:8080
            HiddenServiceSingleHopMode 1
            HiddenServiceNonAnonymousMode 1
            """.trimIndent(),
        )
        val c = TorrcParser.parse(Files.readString(torrc), dir)
        assertEquals(50, c.pathBias.circThreshold)
        assertEquals(0.5, c.pathBias.noticeRate, 1e-9)
        assertTrue(c.serverDns.allowBrokenConfig)
        assertEquals(false, c.serverDns.randomizeCase)
        assertTrue(c.process.dataDirectoryGroupReadable)
        assertTrue(c.process.keyDirectoryGroupReadable)
        assertTrue(c.process.maxMemInQueuesBytes > 0)
        assertTrue(c.process.maxMemInQueuesLowThresholdBytes > 0)
        assertTrue(c.process.addressDisableIPv6)
        assertEquals(10, c.process.logTimeGranularityMs)
        assertEquals(500, c.connLimit)
        assertTrue(c.hiddenServices.first().singleHopMode)
        assertTrue(c.hiddenServices.first().nonAnonymousMode)
    }
}
