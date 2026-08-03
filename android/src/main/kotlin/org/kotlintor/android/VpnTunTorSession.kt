package org.kotlintor.android

import android.os.ParcelFileDescriptor
import kotlinx.coroutines.CoroutineScope
import org.kotlintor.TorClient
import org.kotlintor.net.stack.DefaultOnionTunnelScaffolding
import org.kotlintor.net.stack.OnionTunnel
import org.kotlintor.net.stack.OnionTunnelCommand
import org.kotlintor.net.stack.OnionTunnelScaffolding
import org.kotlintor.net.stack.StreamPacketIo
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress

/**
 * Binds an established VpnService TUN fd to [OnionTunnel] so device IP traffic
 * is handled by the pure-Kotlin userspace stack (TCP → Tor, UDP DNS → fake-IP).
 */
class VpnTunTorSession(
    scope: CoroutineScope,
    client: TorClient,
    tunPfd: ParcelFileDescriptor,
    protect: (Int) -> Boolean = { true },
    private val scaffolding: OnionTunnelScaffolding = AndroidOnionTunnelScaffolding(protect),
) {
    private val tunnel: OnionTunnel = OnionTunnel(
        scope = scope,
        io = StreamPacketIo(
            FileInputStream(tunPfd.fileDescriptor),
            FileOutputStream(tunPfd.fileDescriptor),
        ),
        client = client,
        scaffolding = scaffolding,
    )

    fun start() {
        // Bootstrap gate: protector must already be installed via attachVpn.
        tunnel.markBootstrapped()
        tunnel.start()
    }

    fun stop() = tunnel.stop()
    fun activeFlows(): Int = tunnel.ipStack.activeTcpFlows()
    fun onionTunnel(): OnionTunnel = tunnel

    fun sendCommand(cmd: OnionTunnelCommand): Boolean {
        val sc = scaffolding
        return if (sc is DefaultOnionTunnelScaffolding) sc.offer(cmd) else false
    }
}

/**
 * Android VpnService scaffolding: protect required; isolate by src endpoint hash
 * (UID via getConnectionOwnerUid can replace this later).
 */
class AndroidOnionTunnelScaffolding(
    private val protectFd: (Int) -> Boolean,
) : DefaultOnionTunnelScaffolding() {
    override fun protect(fd: Int): Boolean = protectFd(fd)
    override fun requireProtectAttached(): Boolean = true
    override fun shouldProtect(isolationKey: Long): Boolean = true
    override fun isolate(
        src: InetSocketAddress,
        dst: InetSocketAddress,
        proto: Int,
    ): Long {
        val h = (src.address?.hostAddress?.hashCode() ?: 0).toLong() xor
            (src.port.toLong() shl 16) xor proto.toLong()
        return h and 0x7fff_ffffL
    }
}
