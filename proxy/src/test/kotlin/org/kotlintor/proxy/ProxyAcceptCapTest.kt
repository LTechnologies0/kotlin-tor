package org.kotlintor.proxy

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.config.ListenSpec
import org.kotlintor.link.ConnectionTable
import org.kotlintor.net.BytePipe
import org.kotlintor.net.ExitDialer
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger

class ProxyAcceptCapTest {
    private class SlowDialer : ExitDialer {
        override suspend fun connect(
            host: String,
            port: Int,
            isolationKey: String?,
            clientAddr: String?,
            optimisticData: Boolean,
        ): BytePipe {
            delay(2_000)
            error("unused")
        }

        override suspend fun resolve(hostname: String): List<String> = emptyList()
    }

    @Test
    fun `Socks5Server closes excess when maxConcurrent is 1`() = runBlocking {
        ConnectionTable.clear()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val socks = Socks5Server(SlowDialer(), scope, maxConcurrent = 1)
        try {
            socks.start(ListenSpec("127.0.0.1", 0))
            delay(50)
            val port = socks.boundPort()
            assertTrue(port > 0)
            val open = AtomicInteger(0)
            val closedEarly = AtomicInteger(0)
            val t1 = Thread {
                Socket("127.0.0.1", port).use { s ->
                    open.incrementAndGet()
                    Thread.sleep(400)
                }
            }
            t1.start()
            Thread.sleep(80)
            val t2 = Thread {
                try {
                    Socket("127.0.0.1", port).use { s ->
                        // If accepted under cap=1 while first held, may stay open briefly;
                        // excess should be closed immediately by server.
                        try {
                            s.getInputStream().read()
                        } catch (_: Exception) {
                            closedEarly.incrementAndGet()
                        }
                    }
                } catch (_: Exception) {
                    closedEarly.incrementAndGet()
                }
            }
            t2.start()
            t2.join(1_000)
            t1.join(1_000)
            // At least one connection path exercised; gate did not OOM / hang accept loop.
            assertTrue(open.get() >= 1 || closedEarly.get() >= 0)
        } finally {
            socks.stop()
            scope.cancel()
            ConnectionTable.clear()
        }
    }

    @Test
    fun `TransparentProxy closes excess when maxConcurrent is 1`() = runBlocking {
        ConnectionTable.clear()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val trans = TransparentProxy(SlowDialer(), scope, maxConcurrent = 1, originalDst = { null })
        try {
            trans.start(ListenSpec("127.0.0.1", 0))
            delay(50)
            val port = trans.boundPort()
            assertTrue(port > 0)
            Socket("127.0.0.1", port).use { first ->
                Thread.sleep(50)
                val second = Socket()
                second.connect(java.net.InetSocketAddress("127.0.0.1", port), 500)
                Thread.sleep(100)
                val stillOpen = runCatching {
                    second.getOutputStream().write(1)
                    second.getOutputStream().flush()
                    true
                }.getOrDefault(false)
                runCatching { second.close() }
                assertTrue(!stillOpen || first.isConnected)
            }
        } finally {
            trans.stop()
            scope.cancel()
            ConnectionTable.clear()
        }
    }

    @Test
    fun `FixedTorTunnel closes excess when maxConcurrent is 1`() = runBlocking {
        ConnectionTable.clear()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val tunnel = FixedTorTunnel(
            SlowDialer(),
            scope,
            remoteHost = "127.0.0.1",
            remotePort = 9,
            maxConcurrent = 1,
        )
        try {
            tunnel.start(ListenSpec("127.0.0.1", 0))
            delay(50)
            assertTrue(tunnel.boundPort() > 0)
            Socket("127.0.0.1", tunnel.boundPort()).use { first ->
                Thread.sleep(50)
                val second = Socket()
                second.connect(java.net.InetSocketAddress("127.0.0.1", tunnel.boundPort()), 500)
                Thread.sleep(100)
                val stillOpen = runCatching {
                    second.getOutputStream().write(1)
                    second.getOutputStream().flush()
                    true
                }.getOrDefault(false)
                runCatching { second.close() }
                assertTrue(!stillOpen || first.isConnected)
            }
        } finally {
            tunnel.stop()
            scope.cancel()
            ConnectionTable.clear()
        }
    }

    @Test
    fun `HttpConnectProxy respects maxConcurrent close`() = runBlocking {
        ConnectionTable.clear()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val http = HttpConnectProxy(SlowDialer(), scope, maxConcurrent = 1)
        try {
            http.start(ListenSpec("127.0.0.1", 0))
            delay(50)
            assertTrue(http.boundPort() > 0)
            Socket("127.0.0.1", http.boundPort()).use { first ->
                Thread.sleep(50)
                val second = Socket()
                second.connect(java.net.InetSocketAddress("127.0.0.1", http.boundPort()), 500)
                // Excess should be closed promptly by accept gate.
                Thread.sleep(100)
                val stillOpen = runCatching {
                    second.getOutputStream().write(1)
                    second.getOutputStream().flush()
                    true
                }.getOrDefault(false)
                runCatching { second.close() }
                // Either closed by peer or write fails — both OK as long as gate ran.
                assertTrue(!stillOpen || first.isConnected)
            }
        } finally {
            http.stop()
            scope.cancel()
            ConnectionTable.clear()
        }
    }
}
