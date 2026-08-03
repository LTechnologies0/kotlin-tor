package org.kotlintor.proxy

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.config.ListenSpec
import org.kotlintor.link.ConnectionTable
import org.kotlintor.link.ConnectionType
import org.kotlintor.net.BytePipe
import org.kotlintor.net.ExitDialer

class ProxyListenerElevationTest {
    private class NoopDialer : ExitDialer {
        override suspend fun connect(
            host: String,
            port: Int,
            isolationKey: String?,
            clientAddr: String?,
            optimisticData: Boolean,
        ): BytePipe = error("unused")

        override suspend fun resolve(hostname: String): List<String> = emptyList()
    }

    @Test
    fun `Socks DNS TransPort HttpConnect register AP listeners`() {
        ConnectionTable.clear()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val dialer = NoopDialer()
            val socks = Socks5Server(dialer, scope)
            socks.start(ListenSpec("127.0.0.1", 0))
            val dns = DnsPortServer(dialer, scope)
            dns.start(ListenSpec("127.0.0.1", 0))
            val trans = TransparentProxy(dialer, scope) { null }
            trans.start(ListenSpec("127.0.0.1", 0))
            val http = HttpConnectProxy(dialer, scope)
            http.start(ListenSpec("127.0.0.1", 0))
            val bilingual = BilingualProxyServer(dialer, scope)
            bilingual.start(ListenSpec("127.0.0.1", 0))
            val tunnel = FixedTorTunnel(dialer, scope, "127.0.0.1", 9)
            tunnel.start(ListenSpec("127.0.0.1", 0))
            val udpGw = UdpTorGatewayServer(scope)
            udpGw.start(ListenSpec("127.0.0.1", 0))
            Thread.sleep(80)
            val listeners = ConnectionTable.byType(ConnectionType.LISTENER)
            assertTrue(listeners.size >= 7, "listeners=${listeners.size}")
            assertTrue(socks.boundPort() > 0)
            assertTrue(dns.boundPort() > 0)
            assertTrue(trans.boundPort() > 0)
            assertTrue(http.boundPort() > 0)
            assertTrue(bilingual.boundPort() > 0)
            assertTrue(tunnel.boundPort() > 0)
            assertTrue(udpGw.boundPort() > 0)
            socks.stop()
            dns.stop()
            trans.stop()
            http.stop()
            bilingual.stop()
            tunnel.stop()
            udpGw.stop()
            Thread.sleep(30)
            assertEquals(0, ConnectionTable.byType(ConnectionType.LISTENER).size)
        } finally {
            scope.cancel()
            ConnectionTable.clear()
        }
    }
}
