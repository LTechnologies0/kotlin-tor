package org.kotlintor.android

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.kotlintor.TorDaemon
import org.kotlintor.config.IsolationFlag
import org.kotlintor.config.ListenSpec
import org.kotlintor.config.TorConfig
import org.kotlintor.control.ControlServer
import org.kotlintor.proxy.DnsPortServer
import org.kotlintor.proxy.HttpConnectProxy
import org.kotlintor.proxy.Socks5Server
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Android embed API for OnionVPN / apps. Exposes localhost SOCKS + Control + HTTP CONNECT.
 * Callers must protect uplink sockets from VPN routing when used under VpnService
 * via [socketProtector] / [protectFileDescriptor].
 *
 * OnionVPN [TorEngine.KOTLIN_TOR] binds allocated Socks/DNSCrypt/probe/DNS ports via
 * [startWithPorts] on the existing HEV_SOCKS plane (not a new TunDataPlane).
 */
class KotlinTorEngine(
    private val context: Context,
    private val config: TorConfig = routerDefaultConfig(context),
) {
    private enum class Lifecycle { IDLE, STARTING, RUNNING, STOPPING }

    private var scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var daemon = TorDaemon(config, scope)
    private var socks: Socks5Server? = null
    private val roleSocks = CopyOnWriteArrayList<Socks5Server>()
    private var httpConnect: HttpConnectProxy? = null
    private var control: ControlServer? = null
    private var dnsPort: DnsPortServer? = null
    private val lifecycle = AtomicReference(Lifecycle.IDLE)
    private var startJob: Job? = null
    private val bootstrapped = AtomicBoolean(false)

    /** Optional callback to protect a file descriptor from VPN routing. */
    var socketProtector: ((Int) -> Boolean)? = null

    /** Optional VpnService / OnionVPN tunnel (protect + TUN lifecycle). */
    var vpnTunnel: VpnTunnel? = null
        set(value) {
            field = value
            if (value != null) {
                socketProtector = { fd -> value.protect(fd) }
                org.kotlintor.os.PlatformNatives.socketProtector = socketProtector
                // Prefer Socket-based protect on Android (reliable vs FD reflection).
                org.kotlintor.os.PlatformNatives.socketProtectorSocket = { sock ->
                    value.protectSocket(sock)
                }
            }
        }

    val socksPort: Int get() = socks?.boundPort() ?: -1
    val dnsCryptSocksPort: Int get() = roleSocks.getOrNull(0)?.boundPort() ?: -1
    val probeSocksPort: Int get() = roleSocks.getOrNull(1)?.boundPort() ?: -1
    val dnsPortBound: Int get() = dnsPort?.boundPort() ?: -1
    val httpConnectPort: Int get() = httpConnect?.boundPort() ?: -1
    val controlPort: Int get() = control?.boundPort() ?: -1
    val isRunning: Boolean get() = lifecycle.get() == Lifecycle.RUNNING
    val bootstrapLine: String
        get() = if (bootstrapped.get()) {
            daemon.client.bootstrapTracker.statusLine
        } else {
            "not started"
        }

    /** Attach OnionVPN/VpnService **before** [start] so OR dials are protected. */
    fun attachVpn(tunnel: VpnTunnel) {
        vpnTunnel = tunnel
    }

    fun start(onReady: (() -> Unit)? = null, onError: ((Throwable) -> Unit)? = null) {
        startWithPorts(
            socks = config.socksPorts.firstOrNull() ?: ListenSpec("127.0.0.1", 0),
            dnsCryptSocks = null,
            probeSocks = null,
            dns = config.dnsPort,
            onReady = onReady,
            onError = onError,
        )
    }

    /**
     * Bind allocated loopback ports for OnionVPN HEV_SOCKS + DNSCrypt plane.
     * DNSCrypt must start only after this reports ready (SOCKS + DNSPort up).
     *
     * [onReady] / engine `bootstrapped` fire only when the client reports
     * [org.kotlintor.TorClient.isBootstrapped] (bootstrap [org.kotlintor.BootstrapPhase.DONE]).
     * DisableNetwork starts listeners but does not claim circuit-ready.
     */
    fun startWithPorts(
        socks: ListenSpec,
        dnsCryptSocks: ListenSpec? = null,
        probeSocks: ListenSpec? = null,
        dns: ListenSpec? = null,
        httpTunnel: ListenSpec? = config.httpTunnelPort,
        controlListen: ListenSpec = config.controlPorts.firstOrNull() ?: ListenSpec("127.0.0.1", 0),
        onReady: (() -> Unit)? = null,
        onError: ((Throwable) -> Unit)? = null,
    ) {
        if (!lifecycle.compareAndSet(Lifecycle.IDLE, Lifecycle.STARTING)) return
        ensureScope()
        startJob = scope.launch {
            try {
                requireSafeListener("SocksPort", socks)
                dnsCryptSocks?.let { requireSafeListener("SocksPort(dnsCrypt)", it) }
                probeSocks?.let { requireSafeListener("SocksPort(probe)", it) }
                dns?.let { requireSafeListener("DNSPort", it) }
                val httpSpec = httpTunnel ?: ListenSpec("127.0.0.1", 0)
                requireSafeListener("HTTPTunnelPort", httpSpec)
                requireSafeControl(controlListen)

                // Protector must already be attached when under VPN.
                daemon.start()
                val s = Socks5Server(daemon.client, daemon.scope, optimisticData = config.optimisticData)
                s.start(socks)
                this@KotlinTorEngine.socks = s
                dnsCryptSocks?.let { spec ->
                    val r = Socks5Server(daemon.client, daemon.scope, optimisticData = config.optimisticData)
                    r.start(spec)
                    roleSocks += r
                }
                probeSocks?.let { spec ->
                    val r = Socks5Server(daemon.client, daemon.scope, optimisticData = config.optimisticData)
                    r.start(spec)
                    roleSocks += r
                }
                dns?.let { spec ->
                    val d = DnsPortServer(daemon.client, daemon.scope)
                    d.start(spec)
                    dnsPort = d
                }
                val h = HttpConnectProxy(daemon.client, daemon.scope, optimisticData = config.optimisticData)
                h.start(httpSpec)
                httpConnect = h
                val c = ControlServer(daemon, daemon.scope)
                c.start(controlListen)
                control = c

                if (!lifecycle.compareAndSet(Lifecycle.STARTING, Lifecycle.RUNNING)) {
                    // stop() claimed ownership during start — tear down and exit.
                    teardownPartialStart()
                    bootstrapped.set(false)
                    return@launch
                }

                // Only claim circuit-ready / onReady after DONE (not DisableNetwork-only start).
                val circuitReady = daemon.client.isBootstrapped
                bootstrapped.set(circuitReady)
                if (circuitReady) {
                    onReady?.invoke()
                    runCatching {
                        OrbotCompat.broadcastStatus(
                            context,
                            this@KotlinTorEngine,
                            OrbotCompat.STATUS_ON,
                        )
                    }
                }
            } catch (t: Throwable) {
                teardownPartialStart()
                lifecycle.set(Lifecycle.IDLE)
                bootstrapped.set(false)
                runCatching {
                    context.sendBroadcast(OrbotCompat.errorIntent(context, t.message ?: "start failed"))
                }
                onError?.invoke(t)
            }
        }
    }

    fun stop() {
        while (true) {
            val cur = lifecycle.get()
            when (cur) {
                Lifecycle.IDLE -> {
                    if (socks == null && control == null) return
                    if (!lifecycle.compareAndSet(Lifecycle.IDLE, Lifecycle.STOPPING)) continue
                }
                Lifecycle.STOPPING -> return
                Lifecycle.STARTING, Lifecycle.RUNNING -> {
                    if (!lifecycle.compareAndSet(cur, Lifecycle.STOPPING)) continue
                }
            }
            break
        }
        val job = startJob
        job?.cancel()
        runCatching {
            runBlocking(Dispatchers.IO) { job?.join() }
        }
        startJob = null
        teardownPartialStart()
        vpnTunnel?.teardownTun()
        vpnTunnel = null
        socketProtector = null
        org.kotlintor.os.PlatformNatives.socketProtector = null
        org.kotlintor.os.PlatformNatives.socketProtectorSocket = null
        scope.cancel()
        bootstrapped.set(false)
        lifecycle.set(Lifecycle.IDLE)
    }

    fun newnym() {
        if (!scope.isActive) return
        scope.launch { daemon.signalNewnym() }
    }

    /** VpnService.protect(fd) bridge — returns false if no protector is set. */
    fun protectFileDescriptor(fd: Int): Boolean = socketProtector?.invoke(fd) ?: false

    /** Tor client for TUN / advanced callers (after [start]). */
    fun daemonClient(): org.kotlintor.TorClient = daemon.client

    /** Daemon for events / onion / control demos (after [start]). */
    fun torDaemon(): TorDaemon = daemon

    fun circuitStatusLines(): List<String> =
        if (bootstrapped.get()) daemon.client.circuitStatusLines() else emptyList()

    fun guardStatusLines(): List<String> =
        if (bootstrapped.get()) daemon.client.sampledGuardStatusLines() else emptyList()

    fun setDormant(value: Boolean) {
        if (!bootstrapped.get()) return
        daemon.client.setDormant(value)
    }

    fun bootstrapProgressLine(): String = bootstrapLine

    val dnssecValidate: Boolean
        get() = config.dnssecMode == org.kotlintor.net.dns.DnssecMode.VALIDATE

    private fun ensureScope() {
        if (!scope.isActive) {
            scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
            daemon = TorDaemon(config, scope)
        }
    }

    /** Stop listeners + daemon after a failed or intentional shutdown. */
    private fun teardownPartialStart() {
        runCatching { socks?.stop() }
        socks = null
        roleSocks.forEach { runCatching { it.stop() } }
        roleSocks.clear()
        runCatching { dnsPort?.stop() }
        dnsPort = null
        runCatching { httpConnect?.stop() }
        httpConnect = null
        runCatching { control?.stop() }
        control = null
        // TorDaemon.stop() also cancels [scope]; next start recreates via [ensureScope].
        runCatching { daemon.stop() }
    }

    private fun requireSafeListener(label: String, spec: ListenSpec) {
        if (!spec.isLoopbackHost()) {
            System.err.println(
                "kotlin-tor: warning $label bound to non-loopback ${spec.host} — SNAPSHOT, not production-hardened",
            )
        }
    }

    private fun requireSafeControl(spec: ListenSpec) {
        if (spec.isLoopbackHost()) return
        val cookie = config.cookieAuthentication
        val hashed = !config.hashedControlPassword.isNullOrBlank()
        require(cookie || hashed) {
            "ControlPort on non-loopback ${spec.host} requires CookieAuthentication or HashedControlPassword"
        }
    }

    companion object {
        const val ENGINE_ID = "KOTLIN_TOR"

        /**
         * Loopback router profile (SOCKS + Control). Prefer this name for non-VPN embeds.
         * IsolateSOCKSAuth + allow IP exits for fake-IP cookies when used under OnionTunnel.
         */
        fun routerDefaultConfig(context: Context): TorConfig =
            TorConfig(
                dataDirectory = context.filesDir.resolve("kotlin-tor").toPath(),
                socksPorts = listOf(ListenSpec("127.0.0.1", 0)),
                controlPorts = listOf(ListenSpec("127.0.0.1", 0)),
                isolationFlags = setOf(IsolationFlag.IsolateSOCKSAuth),
                safeSocks = true,
                safeSocksAllowIpLiterals = true,
                // Android has no reliable TCP_INFO/KIST path; Vanilla avoids
                // CREATE2 write-budget deadlocks from empty SocketInfo.
                schedulers = listOf(org.kotlintor.link.SchedulerType.VANILLA),
            )

        /** @deprecated Use [routerDefaultConfig]; kept for OnionVPN call sites. */
        fun vpnDefaultConfig(context: Context): TorConfig = routerDefaultConfig(context)
    }
}
