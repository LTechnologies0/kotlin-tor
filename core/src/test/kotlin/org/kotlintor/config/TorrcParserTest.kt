package org.kotlintor.config

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.file.Path

class TorrcParserTest {
    @Test
    fun `parse common client keys`() {
        val text = """
            DataDirectory /tmp/kt-tor
            SocksPort 127.0.0.1:9050 IsolateSOCKSAuth
            ControlPort 9051
            CookieAuthentication 1
            ClientOnly 1
            ExcludeNodes badrelay
            SafeLogging 1
        """.trimIndent()
        val cfg = TorrcParser.parse(text, Path.of("/tmp/default"))
        assertEquals(Path.of("/tmp/kt-tor"), cfg.dataDirectory)
        assertEquals(9050, cfg.socksPorts.first().port)
        assertTrue(IsolationFlag.IsolateSOCKSAuth in cfg.isolationFlags)
        assertEquals(9051, cfg.controlPorts.first().port)
        assertTrue(cfg.cookieAuthentication)
        assertTrue(cfg.clientOnly)
        assertEquals(listOf("badrelay"), cfg.excludeNodes)
        assertTrue(cfg.safeLogging)
    }

    @Test
    fun `dnsport and optimistic and ctp`() {
        val text = """
            DNSPort 127.0.0.1:5353
            OptimisticData 0
            PublishServerDescriptor 0
            ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
        """.trimIndent()
        val cfg = TorrcParser.parse(text, Path.of("/tmp/d"))
        assertEquals(5353, cfg.dnsPort?.port)
        assertFalse(cfg.optimisticData)
        assertFalse(cfg.publishServerDescriptor)
        assertTrue(cfg.clientTransportPlugin!!.contains("obfs4proxy"))
    }

    @Test
    fun `disable network and build timeout and sandbox keys`() {
        val text = """
            DisableNetwork 1
            CircuitBuildTimeout 90
            MaxClientCircuitsPending 16
            ConnLimit 2048
            KeepalivePeriod 120
            FetchDirInfoEarly 1
            AvoidDiskWrites 1
            DisableDebuggerAttachment 0
            Sandbox 1
        """.trimIndent()
        val cfg = TorrcParser.parse(text, Path.of("/tmp/d"))
        assertTrue(cfg.disableNetwork)
        assertEquals(90L, cfg.circuitBuildTimeoutSec)
        assertEquals(16, cfg.maxClientCircuitsPending)
        assertEquals(2048, cfg.connLimit)
        assertEquals(120L, cfg.keepalivePeriodSec)
        assertTrue(cfg.fetchDirInfoEarly)
        assertTrue(cfg.avoidDiskWrites)
        assertFalse(cfg.disableDebuggerAttachment)
        assertTrue(cfg.sandbox)
    }

    @Test
    fun `manpage keys land in acknowledgedKeys`() {
        val text = """
            SchedulerWindowSize 100
            TotallyFakeOption 1
            Nickname MyRelay
            ContactInfo ops@example.invalid
            BandwidthRate 2 MB
            LearnCircuitBuildTimeout 0
        """.trimIndent()
        val cfg = TorrcParser.parse(text, Path.of("/tmp/d"))
        assertTrue(cfg.acknowledgedKeys.containsKey("SchedulerWindowSize"))
        assertEquals("1", cfg.unrecognizedKeys["TotallyFakeOption"])
        assertEquals("MyRelay", cfg.nickname)
        assertEquals("ops@example.invalid", cfg.contactInfo)
        assertEquals(2_000_000L, cfg.bandwidthRateBytes)
        assertFalse(cfg.learnCircuitBuildTimeout)
    }
}
