package org.kotlintor.os

import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import java.net.Socket

class SocketFdExtractTest {
    @Test
    fun `socketFd finds NioSocketImpl fd via SocksSocketImpl delegate after bind`() {
        assumeTrue(
            System.getProperty("os.name").lowercase().contains("linux") ||
                System.getProperty("os.name").lowercase().contains("mac"),
        )
        Socket().use { sock ->
            sock.bind(InetSocketAddress(0))
            val fd = PlatformNatives.socketFd(sock)
            assertNotNull(fd, "JDK SocksSocketImpl.delegate.fd must be visible with --add-opens")
            assertTrue(fd!! >= 0, "fd=$fd")
        }
    }

    @Test
    fun `SO_MARK setsockopt succeeds on bound socket when CAP_NET_ADMIN available`() {
        assumeTrue(System.getProperty("os.name").lowercase().contains("linux"))
        Socket().use { sock ->
            sock.bind(InetSocketAddress(0))
            val fd = PlatformNatives.socketFd(sock)
            assumeTrue(fd != null && fd >= 0, "FD extract required")
            val ok = LinuxSocketMarkProtector.setMark(fd!!, LinuxSocketMarkProtector.DEFAULT_FWMARK)
            if (!ok && PlatformNatives.lastProtectFailure?.contains("errno=1") == true) {
                assumeTrue(false, "SO_MARK needs CAP_NET_ADMIN (sudo); skip unprivileged CI")
            }
            assertTrue(ok, PlatformNatives.lastProtectFailure ?: "setMark failed")
        }
    }
}
