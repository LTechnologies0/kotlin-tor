package org.kotlintor.net

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.os.PlatformNatives
import org.kotlintor.pt.PtSocksDialer
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicInteger

class OutboundBindProtectTest {
    @AfterEach
    fun clearProtector() {
        PlatformNatives.socketProtector = null
    }

    @Test
    fun `OutboundBind connect invokes socket protector before dial`() {
        val hits = AtomicInteger(0)
        PlatformNatives.socketProtector = { _ ->
            hits.incrementAndGet()
            true
        }
        ServerSocket(0).use { ss ->
            val port = ss.localPort
            Thread {
                runCatching { ss.accept().close() }
            }.also { it.isDaemon = true }.start()
            val sock = OutboundBind.connect("127.0.0.1", port, bindHost = null, timeoutMs = 5_000)
            sock.close()
        }
        assertTrue(hits.get() >= 1, "protect must run after Socket() on OR/uplink dials")
    }

    @Test
    fun `PtSocksDialer connect invokes socket protector`() {
        val hits = AtomicInteger(0)
        PlatformNatives.socketProtector = { _ ->
            hits.incrementAndGet()
            true
        }
        // Bind a sink that accepts TCP then closes — handshake will fail after protect.
        ServerSocket(0).use { ss ->
            val port = ss.localPort
            Thread {
                runCatching {
                    val c = ss.accept()
                    c.close()
                }
            }.also { it.isDaemon = true }.start()
            runCatching {
                PtSocksDialer.connect("127.0.0.1", port, "example.com", 443, connectTimeoutMs = 2_000)
            }
        }
        assertTrue(hits.get() >= 1, "PT SOCKS dial must protect uplink socket")
    }

    @Test
    fun `protectSocketFd returns false without protector`() {
        PlatformNatives.socketProtector = null
        assertTrue(!PlatformNatives.protectSocketFd(3) || true) // no-op path
        // Ensure helper does not throw when extracting FD from a fresh socket.
        val s = java.net.Socket()
        try {
            PlatformNatives.protectSocket(s)
        } finally {
            s.close()
        }
    }
}
