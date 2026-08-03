package org.kotlintor.net.stack

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import java.net.InetSocketAddress

/**
 * Onionmasq-shaped scaffolding for [OnionTunnel] (pure Kotlin, no JNI).
 */
interface OnionTunnelScaffolding {
    /** Protect [fd] from VPN capture (VpnService.protect). */
    fun protect(fd: Int): Boolean = true

    /** When false, clearnet leak for this isolation key is intentional. */
    fun shouldProtect(isolationKey: Long): Boolean = true

    /**
     * When true, [OnionTunnel] refuses TCP until [org.kotlintor.os.PlatformNatives.socketProtector]
     * is installed (bootstrap gate). JVM MemoryTun tests leave this false.
     */
    fun requireProtectAttached(): Boolean = false

    /** Map connection endpoints → isolation key (typically Android UID). */
    fun isolate(
        src: InetSocketAddress,
        dst: InetSocketAddress,
        proto: Int,
    ): Long = 0L

    fun onBootstrapped() {}
    fun onEstablished(isolationKey: Long, dstHost: String, dstPort: Int) {}
    fun onFailure(isolationKey: Long, dstHost: String, dstPort: Int, error: Throwable) {}
    fun onSocketClose(isolationKey: Long) {}

    /** Optional command source; null = no command loop. */
    fun commandStream(): Flow<OnionTunnelCommand>? = null
}

sealed class OnionTunnelCommand {
    data object RefreshCircuits : OnionTunnelCommand()
    data class RefreshCircuitsForApp(val isolationKey: Long) : OnionTunnelCommand()
    data class SetDormant(val dormant: Boolean) : OnionTunnelCommand()
}

/**
 * Default scaffolding with an in-memory command channel for tests / VpnService.
 */
open class DefaultOnionTunnelScaffolding : OnionTunnelScaffolding {
    private val commands = Channel<OnionTunnelCommand>(Channel.BUFFERED)
    @Volatile var dormant: Boolean = false
        private set
    @Volatile var bootstrapped: Boolean = false
        private set

    override fun onBootstrapped() {
        bootstrapped = true
    }

    override fun commandStream(): Flow<OnionTunnelCommand> = commands.receiveAsFlow()

    suspend fun send(cmd: OnionTunnelCommand) {
        commands.send(cmd)
    }

    fun offer(cmd: OnionTunnelCommand): Boolean = commands.trySend(cmd).isSuccess

    internal fun applyDormant(value: Boolean) {
        dormant = value
    }
}
