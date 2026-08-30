package org.kotlintor.demo

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.onSubscription
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.kotlintor.TorDaemon
import org.kotlintor.TorEvent
import org.kotlintor.config.ListenSpec
import org.kotlintor.config.TorConfig
import org.kotlintor.control.ControlServer
import org.kotlintor.net.dns.DnssecMode
import org.kotlintor.proxy.DnsPortServer
import org.kotlintor.proxy.HttpConnectProxy
import org.kotlintor.proxy.Socks5Server
import java.nio.file.Files
import java.nio.file.Path

data class DemoPorts(
    val socks: Int = -1,
    val http: Int = -1,
    val dns: Int = -1,
    val control: Int = -1,
)

data class DemoSessionOptions(
    val dataDirectory: Path,
    val dnssecValidate: Boolean = false,
    val dnssecRecursive: String = "1.1.1.1:53",
    val useMicrodescriptors: Boolean = false,
)

/**
 * Owns a loopback Tor demo session: daemon + SOCKS + HTTP CONNECT + DNSPort + Control.
 * Shared by Android and Desktop shells (not VpnService).
 */
class DemoSession {
    private val mutex = Mutex()
    private var daemon: TorDaemon? = null
    private var socks: Socks5Server? = null
    private var http: HttpConnectProxy? = null
    private var dns: DnsPortServer? = null
    private var control: ControlServer? = null
    private var eventJob: Job? = null
    private var running = false

    val isRunning: Boolean get() = running
    val torDaemon: TorDaemon? get() = daemon

    fun bootstrapLine(): String =
        daemon?.client?.bootstrapTracker?.statusLine ?: "not started"

    fun ports(): DemoPorts = DemoPorts(
        socks = socks?.boundPort() ?: -1,
        http = http?.boundPort() ?: -1,
        dns = dns?.boundPort() ?: -1,
        control = control?.boundPort() ?: -1,
    )

    fun dnssecValidate(): Boolean =
        daemon?.config?.dnssecMode == DnssecMode.VALIDATE

    fun dnssecRecursive(): String =
        daemon?.config?.dnssecRecursive ?: "1.1.1.1:53"

    suspend fun start(options: DemoSessionOptions) = mutex.withLock {
        if (running) return
        Files.createDirectories(options.dataDirectory)
        val config = TorConfig(
            dataDirectory = options.dataDirectory,
            socksPorts = listOf(ListenSpec("127.0.0.1", 0)),
            controlPorts = listOf(ListenSpec("127.0.0.1", 0)),
            httpTunnelPort = ListenSpec("127.0.0.1", 0),
            dnsPort = ListenSpec("127.0.0.1", 0),
            cookieAuthentication = true,
            clientOnly = true,
            useMicrodescriptors = options.useMicrodescriptors,
            dnssecMode = if (options.dnssecValidate) DnssecMode.VALIDATE else DnssecMode.OFF,
            dnssecRecursive = options.dnssecRecursive,
            isolationFlags = setOf(org.kotlintor.config.IsolationFlag.IsolateSOCKSAuth),
            safeSocks = true,
            safeSocksAllowIpLiterals = true,
        )
        val d = TorDaemon(config)
        try {
            // Subscribe before start so bootstrap CIRC/boot events are not dropped.
            val eventsReady = CompletableDeferred<Unit>()
            eventJob = mirrorEvents(d, eventsReady)
            eventsReady.await()
            DemoLogBuffer.append("session", "starting tor…")
            d.start(buildCircuit = true)
            val s = Socks5Server(d.client, d.scope, optimisticData = config.optimisticData)
            s.start(ListenSpec("127.0.0.1", 0))
            val h = HttpConnectProxy(d.client, d.scope, optimisticData = config.optimisticData)
            h.start(ListenSpec("127.0.0.1", 0))
            val dn = DnsPortServer(d.client, d.scope)
            dn.start(ListenSpec("127.0.0.1", 0))
            val c = ControlServer(d, d.scope)
            c.start(ListenSpec("127.0.0.1", 0))
            daemon = d
            socks = s
            http = h
            dns = dn
            control = c
            running = true
            val ports = ports()
            DemoLogBuffer.append(
                "session",
                "started ${d.client.bootstrapTracker.statusLine} " +
                    "socks=${ports.socks} http=${ports.http} dns=${ports.dns} control=${ports.control}",
            )
        } catch (t: Throwable) {
            eventJob?.cancel()
            eventJob = null
            runCatching { d.stop() }
            throw t
        }
    }

    suspend fun stop() = mutex.withLock {
        if (!running && daemon == null) return
        eventJob?.cancel()
        eventJob = null
        runCatching { dns?.stop() }
        runCatching { http?.stop() }
        runCatching { socks?.stop() }
        runCatching { control?.stop() }
        runCatching { daemon?.stop() }
        dns = null
        http = null
        socks = null
        control = null
        daemon = null
        running = false
        DemoLogBuffer.append("session", "stopped")
    }

    /** Mirror control-style Tor events into the demo log ring (one line each). */
    private fun mirrorEvents(d: TorDaemon, ready: CompletableDeferred<Unit>? = null): Job =
        CoroutineScope(d.scope.coroutineContext).launch {
            d.events
                .onSubscription { ready?.complete(Unit) }
                .collect { ev ->
                    when (ev) {
                        is TorEvent.Circ -> DemoLogBuffer.append("circ", ev.line)
                        is TorEvent.CircMinor -> DemoLogBuffer.append("circ", ev.line)
                        is TorEvent.Notice -> DemoLogBuffer.append("notice", ev.message)
                        is TorEvent.Warn -> DemoLogBuffer.append("warn", ev.message)
                        is TorEvent.Bootstrap -> DemoLogBuffer.append("boot", ev.line)
                        is TorEvent.OrConn -> DemoLogBuffer.append("orconn", ev.line)
                        is TorEvent.Stream -> DemoLogBuffer.append("stream", ev.line)
                        is TorEvent.HsDesc -> DemoLogBuffer.append("hs", ev.line)
                        else -> Unit
                    }
                }
        }
}
