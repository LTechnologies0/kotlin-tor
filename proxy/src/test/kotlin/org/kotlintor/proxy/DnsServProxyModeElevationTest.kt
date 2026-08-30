package org.kotlintor.proxy

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.config.ListenSpec
import org.kotlintor.config.TorConfig
import java.nio.file.Files

/** Elevates L1:feature/client/dnsserv.c and L1:feature/client/proxymode.c */
class DnsServProxyModeElevationTest {
    @Test
    fun `dnsserv onion automap`() {
        assertTrue(DnsServ.isOnion("foo.onion"))
        assertTrue(DnsServ.shouldAutomap("bar.exit"))
        assertFalse(DnsServ.shouldAutomap("example.com"))
    }

    @Test
    fun `proxymode flags`() {
        val cfg = TorConfig(
            dataDirectory = Files.createTempDirectory("ktor-pm"),
            socksPorts = listOf(ListenSpec("127.0.0.1", 9050)),
            dnsPort = ListenSpec("127.0.0.1", 5353),
        )
        assertTrue(ProxyMode.socksEnabled(cfg))
        assertTrue(ProxyMode.dnsPortEnabled(cfg))
        assertTrue(ProxyMode.anyClientProxy(cfg))
        assertTrue(ProxyMode.proxyMode(cfg))
        assertFalse(ProxyMode.httpTunnelEnabled(cfg))
    }
}
