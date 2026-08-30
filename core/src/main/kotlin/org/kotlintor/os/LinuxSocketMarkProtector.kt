package org.kotlintor.os

import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.net.Socket

/**
 * Tor-uplink-only exclusion from a Linux full-tunnel VPN.
 *
 * Marks sockets with [SO_MARK] so policy routing ([LinuxTunRoutes]) sends them
 * via the pre-VPN physical default route. Only OR/PT dials that go through
 * [org.kotlintor.net.OutboundBind.connect] / [PlatformNatives.protectSocket] are marked.
 */
class LinuxSocketMarkProtector(
    val fwmark: Int = DEFAULT_FWMARK,
) {
    fun protectFd(fd: Int): Boolean {
        if (fd < 0) {
            PlatformNatives.lastProtectFailure = "invalid fd=$fd"
            return false
        }
        return setMark(fd, fwmark)
    }

    fun protectSocket(socket: Socket): Boolean {
        val fd = PlatformNatives.socketFd(socket)
        if (fd == null) {
            PlatformNatives.lastProtectFailure =
                "socketFd null (need --add-opens java.base/java.net + SocksSocketImpl.delegate)"
            return false
        }
        return protectFd(fd)
    }

    /** Install as [PlatformNatives] hooks for the VPN session lifetime. */
    fun attachToPlatform() {
        PlatformNatives.socketProtectorSocket = { sock ->
            if (!sock.isBound) {
                runCatching { sock.bind(java.net.InetSocketAddress(0)) }
            }
            protectSocket(sock)
        }
        PlatformNatives.socketProtector = { fd -> protectFd(fd) }
    }

    fun detachFromPlatform() {
        PlatformNatives.socketProtector = null
        PlatformNatives.socketProtectorSocket = null
    }

    companion object {
        const val DEFAULT_FWMARK: Int = 0x6b74 // "kt"

        private const val SOL_SOCKET = 1
        private const val SO_MARK = 36

        fun setMark(fd: Int, mark: Int): Boolean {
            if (fd < 0) {
                PlatformNatives.lastProtectFailure = "invalid fd=$fd"
                return false
            }
            return try {
                Arena.ofConfined().use { arena ->
                    val linker = Linker.nativeLinker()
                    val setsockopt = linker.defaultLookup().find("setsockopt").orElse(null)
                    if (setsockopt == null) {
                        PlatformNatives.lastProtectFailure =
                            "setsockopt symbol missing (need --enable-preview on JDK 21)"
                        return false
                    }
                    val mh = linker.downcallHandle(
                        setsockopt,
                        FunctionDescriptor.of(
                            ValueLayout.JAVA_INT,
                            ValueLayout.JAVA_INT,
                            ValueLayout.JAVA_INT,
                            ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS,
                            ValueLayout.JAVA_INT,
                        ),
                    )
                    val errnoLoc = linker.defaultLookup().find("__errno_location").orElse(null)
                    val errnoMh = errnoLoc?.let {
                        linker.downcallHandle(it, FunctionDescriptor.of(ValueLayout.ADDRESS))
                    }
                    if (errnoMh != null) {
                        val errnoPtr = (errnoMh.invoke() as MemorySegment).reinterpret(4)
                        errnoPtr.set(ValueLayout.JAVA_INT, 0L, 0)
                    }
                    val markSeg = arena.allocate(ValueLayout.JAVA_INT)
                    markSeg.set(ValueLayout.JAVA_INT, 0L, mark)
                    val rc = mh.invoke(fd, SOL_SOCKET, SO_MARK, markSeg, 4) as Int
                    if (rc != 0) {
                        val err = errnoMh?.let {
                            ((it.invoke() as MemorySegment).reinterpret(4)).get(ValueLayout.JAVA_INT, 0L)
                        }
                        PlatformNatives.lastProtectFailure =
                            "setsockopt(SO_MARK) rc=$rc fd=$fd errno=$err" +
                                if (err == 1) " (EPERM: need CAP_NET_ADMIN / sudo)" else ""
                        return false
                    }
                    PlatformNatives.lastProtectFailure = null
                    true
                }
            } catch (t: Throwable) {
                PlatformNatives.lastProtectFailure = "${t.javaClass.simpleName}: ${t.message}"
                false
            }
        }
    }
}
