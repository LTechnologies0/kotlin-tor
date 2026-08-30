package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.net.HaproxyProxyHeader
import java.io.ByteArrayOutputStream
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Elevates `L1:core/proto/proto_haproxy.c` toward D3.
 *
 * Evidence: format matches C Tor `haproxy_format_proxy_header_line` +
 * OutboundBind TCPProxy inject path.
 */
class ProtoHaproxyElevationTest {
    @Test
    fun `haproxy_format_proxy_header_line matches C Tor vector`() {
        assertEquals(
            "PROXY TCP4 0.0.0.0 127.0.0.1 0 12345\r\n",
            HaproxyProxyHeader.formatProxyHeaderLine("127.0.0.1", 12345),
        )
        assertEquals(
            "PROXY TCP6 :: 2001:db8::1 0 9001\r\n",
            HaproxyProxyHeader.formatProxyHeaderLine("2001:db8::1", 9001),
        )
        assertNull(HaproxyProxyHeader.formatProxyHeaderLine("example.com", 443))
        assertNull(HaproxyProxyHeader.formatProxyHeaderLine("1.2.3.4", 0))
    }

    @Test
    fun `TCPProxy inject writes PROXY before payload`() {
        val ss = ServerSocket(0)
        val port = ss.localPort
        val got = ByteArrayOutputStream()
        val pool = Executors.newSingleThreadExecutor()
        val fut = pool.submit {
            ss.accept().use { c ->
                val buf = ByteArray(128)
                val n = c.getInputStream().read(buf)
                if (n > 0) got.write(buf, 0, n)
            }
        }
        try {
            org.kotlintor.net.OutboundBind.connect(
                remoteHost = "127.0.0.1",
                remotePort = 9001,
                bindHost = null,
                tcpProxyHost = "127.0.0.1",
                tcpProxyPort = port,
                tcpProxyProtocol = "haproxy",
                protect = false,
            ).use { /* closed after inject */ }
            fut.get(3, TimeUnit.SECONDS)
            val text = got.toString(Charsets.US_ASCII)
            assertTrue(text.startsWith("PROXY TCP4 0.0.0.0 127.0.0.1 0 9001\r\n"), text)
        } finally {
            ss.close()
            pool.shutdownNow()
        }
    }
}
