package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.config.AutoBool
import org.kotlintor.config.TorrcParser
import org.kotlintor.net.AddrPolicy
import org.kotlintor.net.SafeSocksPolicy
import java.nio.file.Path

class NetworkPolicyElevationTest {
    @Test
    fun `typed Address OutboundBind FascistFirewall SafeSocks Reachable`() {
        val cfg = TorrcParser.parse(
            """
            DataDirectory /tmp/kt
            Address 203.0.113.10
            OutboundBindAddress 127.0.0.1
            OutboundBindAddressOR 127.0.0.2
            OutboundBindAddressExit 127.0.0.3
            OutboundBindAddressPT 127.0.0.4
            FascistFirewall 1
            FirewallPorts 80,443,9001
            ReachableORAddresses accept *:9001
            SafeSocks 1
            TestSocks 1
            WarnUnsafeSocks 0
            SocksTimeout 60
            MaxAdvertisedBandwidth 500 KB
            RelayBandwidthRate 1 MB
            PerConnBWRate 100 KB
            CookieAuthFile /tmp/kt/control_auth_cookie
            KeyDirectory /tmp/kt/keys
            CacheDirectory /tmp/kt/cache
            PublishHidServDescriptors 0
            Padding auto
            CircuitIdleTimeout 1800
            CircuitStreamTimeout 300
            """.trimIndent(),
            Path.of("/tmp/kt"),
        )
        assertEquals("203.0.113.10", cfg.address)
        assertEquals("127.0.0.1", cfg.outboundBindAddress)
        assertEquals("127.0.0.2", cfg.outboundBindForOr())
        assertEquals("127.0.0.3", cfg.outboundBindForExit())
        assertEquals("127.0.0.4", cfg.outboundBindForPt())
        assertTrue(cfg.fascistFirewall)
        assertEquals(setOf(80, 443, 9001), cfg.firewallPorts)
        assertTrue(cfg.safeSocks)
        assertTrue(cfg.testSocks)
        assertFalse(cfg.warnUnsafeSocks)
        assertEquals(60L, cfg.socksTimeoutSec)
        assertEquals(500_000L, cfg.maxAdvertisedBandwidthBytes)
        assertEquals(1_000_000L, cfg.relayBandwidthRateBytes)
        assertEquals(100_000L, cfg.perConnBwRateBytes)
        assertEquals(Path.of("/tmp/kt/control_auth_cookie"), cfg.cookieAuthFile)
        assertEquals(Path.of("/tmp/kt/keys"), cfg.keyDirectory)
        assertFalse(cfg.publishHidServDescriptors)
        assertEquals(AutoBool.AUTO, cfg.padding)
        assertEquals(1800L, cfg.circuitIdleTimeoutSec)
        assertEquals(300L, cfg.circuitStreamTimeoutSec)
        val fascist = cfg.orReachablePolicy()
        assertTrue(fascist.allows("1.2.3.4", 443))
        assertTrue(fascist.allows("1.2.3.4", 9001))
        assertFalse(fascist.allows("1.2.3.4", 22))
    }

    @Test
    fun `SafeSocksPolicy rejects IP literals`() {
        assertTrue(SafeSocksPolicy.isIpLiteral("1.2.3.4"))
        assertFalse(SafeSocksPolicy.isIpLiteral("example.com"))
        assertFalse(SafeSocksPolicy.allows("8.8.8.8", safeSocks = true))
        assertTrue(SafeSocksPolicy.allows("example.com", safeSocks = true))
        assertTrue(SafeSocksPolicy.allows("x.onion", safeSocks = true))
        assertTrue(SafeSocksPolicy.allows("10.1.2.3", safeSocks = true, allowIpLiterals = true))
    }

    @Test
    fun `AddrPolicy ReachableORAddresses`() {
        val p = AddrPolicy.parseLines(listOf("accept *:9001", "accept 10.0.0.0/8:*"))
        assertTrue(p.allows("1.1.1.1", 9001))
        assertFalse(p.allows("1.1.1.1", 80))
        assertTrue(p.allows("10.1.2.3", 22))
    }

    @Test
    fun `ReachableAddresses without Fascist`() {
        val cfg = TorrcParser.parse(
            """
            DataDirectory /tmp/kt
            ReachableORAddresses accept *:443
            """.trimIndent(),
            Path.of("/tmp/kt"),
        )
        assertFalse(cfg.fascistFirewall)
        val p = cfg.orReachablePolicy()
        assertTrue(p.allows("8.8.8.8", 443))
        assertFalse(p.allows("8.8.8.8", 80))
    }
}
