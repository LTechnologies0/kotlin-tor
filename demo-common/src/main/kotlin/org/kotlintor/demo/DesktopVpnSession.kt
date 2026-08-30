package org.kotlintor.demo

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.onSubscription
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.kotlintor.TorDaemon
import org.kotlintor.TorEvent
import org.kotlintor.config.IsolationFlag
import org.kotlintor.config.ListenSpec
import org.kotlintor.config.TorConfig
import org.kotlintor.net.stack.DefaultOnionTunnelScaffolding
import org.kotlintor.net.stack.OnionTunnel
import org.kotlintor.net.stack.StreamPacketIo
import org.kotlintor.os.LinuxSocketMarkProtector
import org.kotlintor.os.LinuxTunDevice
import org.kotlintor.os.LinuxTunRoutes
import org.kotlintor.os.PlatformNatives
import java.net.InetSocketAddress
import java.nio.file.Files
import java.nio.file.Path

/**
 * Linux full-tunnel VPN demo session: TUN → [OnionTunnel] → Tor.
 *
 * Only Tor OR/PT uplink sockets are excluded (SO_MARK + policy routing).
 * Mutually exclusive with [DemoSession] — callers must enforce in UI.
 */
class DesktopVpnSession {
    private val mutex = Mutex()
    private var scope: CoroutineScope? = null
    private var daemon: TorDaemon? = null
    private var tun: LinuxTunDevice? = null
    private var routes: LinuxTunRoutes? = null
    private var protector: LinuxSocketMarkProtector? = null
    private var tunnel: OnionTunnel? = null
    private var running = false
    private var statusLine: String = "Idle"

    val isRunning: Boolean get() = running
    val status: String get() = statusLine
    val torDaemon: TorDaemon? get() = daemon
    val tunName: String? get() = tun?.name

    fun bootstrapLine(): String =
        daemon?.client?.bootstrapTracker?.statusLine ?: statusLine

    companion object {
        fun availabilityMessage(): String? {
            if (!LinuxTunDevice.isLinux()) {
                return "Full-tunnel VPN requires Linux (/dev/net/tun)."
            }
            if (!LinuxTunDevice.canOpen()) {
                return "/dev/net/tun is not available."
            }
            if (!LinuxTunRoutes.hasIpBinary()) {
                return "iproute2 (`ip`) is required for full-tunnel routes."
            }
            return null
        }

        fun isSupported(): Boolean = availabilityMessage() == null
    }

    suspend fun start(dataDirectory: Path) = mutex.withLock {
        if (running) return
        availabilityMessage()?.let { error(it) }

        val r = LinuxTunRoutes()
        val mark = LinuxSocketMarkProtector()
        val sc = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        var d: TorDaemon? = null
        var device: LinuxTunDevice? = null
        var onion: OnionTunnel? = null

        try {
            statusLine = "Preparing protect table…"
            DemoLogBuffer.append("vpn", statusLine)
            val snap = r.snapshotPhysicalDefault()
            r.installProtectTable(snap)
            mark.attachToPlatform()

            Files.createDirectories(dataDirectory)
            val config = TorConfig(
                dataDirectory = dataDirectory,
                socksPorts = listOf(ListenSpec("127.0.0.1", 0)),
                controlPorts = listOf(ListenSpec("127.0.0.1", 0)),
                cookieAuthentication = true,
                clientOnly = true,
                useMicrodescriptors = false,
                isolationFlags = setOf(IsolationFlag.IsolateSOCKSAuth),
                safeSocks = true,
                safeSocksAllowIpLiterals = true,
            )
            d = TorDaemon(config)
            statusLine = "Starting Tor (uplink marked)…"
            DemoLogBuffer.append("vpn", statusLine)
            // Collect before start so bootstrap CIRC/boot events are not dropped.
            val eventsReady = CompletableDeferred<Unit>()
            sc.launch {
                d.events
                    .onSubscription { eventsReady.complete(Unit) }
                    .collect { ev ->
                        when (ev) {
                            is TorEvent.Circ -> DemoLogBuffer.append("circ", ev.line)
                            is TorEvent.Bootstrap -> DemoLogBuffer.append("boot", ev.line)
                            is TorEvent.Warn -> DemoLogBuffer.append("warn", ev.message)
                            is TorEvent.Notice -> DemoLogBuffer.append("notice", ev.message)
                            else -> Unit
                        }
                    }
            }
            eventsReady.await()
            d.start(buildCircuit = true)
            if (!d.client.isBootstrapped) {
                error("Tor failed to bootstrap before TUN — refusing full-tunnel")
            }

            statusLine = "Creating TUN…"
            DemoLogBuffer.append("vpn", statusLine)
            device = LinuxTunDevice.open("ktor0")
            r.configureTunAddress(device.name)
            r.installDefaultViaTun(device.name)

            check(PlatformNatives.hasSocketProtector()) { "SO_MARK protector missing" }
            onion = OnionTunnel(
                scope = sc,
                io = StreamPacketIo(device.inputStream, device.outputStream),
                client = d.client,
                scaffolding = LinuxOnionTunnelScaffolding(),
            )
            onion.markBootstrapped()
            onion.start()

            scope = sc
            daemon = d
            tun = device
            routes = r
            protector = mark
            tunnel = onion
            running = true
            statusLine = "VPN ready — ${device.name} · ${d.client.bootstrapTracker.statusLine}"
            DemoLogBuffer.append("vpn", statusLine)
        } catch (t: Throwable) {
            statusLine = "VPN error: ${t.message}"
            DemoLogBuffer.append("vpn", statusLine)
            runCatching { onion?.stop() }
            runCatching { r.teardown() }
            runCatching { device?.close() }
            runCatching { d?.stop() }
            mark.detachFromPlatform()
            sc.cancel()
            throw t
        }
    }

    suspend fun stop() = mutex.withLock {
        if (!running && daemon == null) return
        statusLine = "Stopping VPN…"
        DemoLogBuffer.append("vpn", statusLine)
        runCatching { tunnel?.stop() }
        runCatching { routes?.teardown() }
        runCatching { tun?.close() }
        runCatching { daemon?.stop() }
        protector?.detachFromPlatform()
        scope?.cancel()
        tunnel = null
        routes = null
        tun = null
        daemon = null
        protector = null
        scope = null
        running = false
        statusLine = "Idle"
        DemoLogBuffer.append("vpn", "stopped")
    }
}

/** Linux full-tunnel scaffolding: protect required (SO_MARK via PlatformNatives). */
class LinuxOnionTunnelScaffolding : DefaultOnionTunnelScaffolding() {
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
