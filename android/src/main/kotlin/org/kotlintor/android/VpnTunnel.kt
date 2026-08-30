package org.kotlintor.android

/**
 * Hook surface for OnionVPN / VpnService integration.
 *
 * Apps implement [VpnTunnel] and call [KotlinTorEngine.attachVpn] so uplink
 * sockets are protected and DNS/SOCKS destinations route through Tor.
 *
 * [OnionTunnel] (in-process TUN NI) uses the same protect path via
 * [org.kotlintor.os.PlatformNatives.socketProtector].
 */
interface VpnTunnel {
    /** Protect [fd] from VPN routing (VpnService.protect). */
    fun protect(fd: Int): Boolean

    /** Prefer this on Android — [android.net.VpnService.protect(Socket)]. */
    fun protectSocket(socket: java.net.Socket): Boolean = protect(
        org.kotlintor.os.PlatformNatives.socketFd(socket) ?: -1,
    )

    /** Optional: establish TUN and return its fd; null if engine should not manage TUN. */
    fun establishTun(mtu: Int = 1500): Int? = null

    fun teardownTun() {}
}
