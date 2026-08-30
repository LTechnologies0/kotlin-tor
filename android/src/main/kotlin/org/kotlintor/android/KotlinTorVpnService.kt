package org.kotlintor.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.kotlintor.config.ListenSpec
import org.kotlintor.config.TorConfig
import org.kotlintor.net.stack.FakeIpDnsCookies
import org.kotlintor.os.PlatformNatives
import java.net.InetAddress

/**
 * VpnService base for TUN capture + Tor handoff.
 *
 * Subclasses call [prepare] from an Activity, then [startService]. Protect is
 * installed **before** bootstrap OR dials. When [useUserspaceTunStack] is true,
 * TUN packets go through [OnionTunnel] after Tor is ready.
 */
abstract class KotlinTorVpnService : VpnService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var engine: KotlinTorEngine? = null
    private var tun: ParcelFileDescriptor? = null
    private var tunSession: VpnTunTorSession? = null
    @Volatile private var starting = false

    protected open fun createEngine(): KotlinTorEngine {
        val cfg = vpnEngineConfig(applicationContext)
        return KotlinTorEngine(applicationContext, cfg)
    }

    /** When true (default), TUN packets go through [OnionTunnel] / userspace IP stack. */
    protected open fun useUserspaceTunStack(): Boolean = true

    protected open fun sessionName(): String = "kotlin-tor"

    protected open fun notificationChannelId(): String = "kotlin_tor_vpn"

    protected open fun notificationId(): Int = 0x6b74 // "kt"

    /** Configure Intent for the VPN notification gear (optional). */
    protected open fun configureIntent(): PendingIntent? = null

    /**
     * Destinations kept off-TUN (API 33+ [Builder.excludeRoute]).
     * Demo excludes the Waydroid/emulator host bridge so ADB survives full-tunnel.
     * Do **not** exclude `10.0.0.0/8` — fake-IP cookies live there.
     */
    protected open fun excludedIpv4Prefixes(): List<Pair<String, Int>> = emptyList()

    fun attachEngine(eng: KotlinTorEngine = createEngine()) {
        engine = eng
        eng.attachVpn(object : VpnTunnel {
            override fun protect(fd: Int): Boolean =
                this@KotlinTorVpnService.protect(fd)

            override fun protectSocket(socket: java.net.Socket): Boolean =
                this@KotlinTorVpnService.protect(socket)

            override fun establishTun(mtu: Int): Int? {
                val b = Builder()
                    .setSession(sessionName())
                    .setMtu(mtu)
                    .setBlocking(true)
                    .addAddress(TUN_IPV4, 32)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer(FakeIpDnsCookies.FAKE_RESOLVER_V4)
                if (Build.VERSION.SDK_INT >= 29) {
                    b.setMetered(false)
                }
                if (Build.VERSION.SDK_INT >= 33) {
                    for ((cidr, prefix) in excludedIpv4Prefixes()) {
                        runCatching {
                            val addr = InetAddress.getByName(cidr)
                            b.excludeRoute(IpPrefix(addr, prefix))
                        }
                    }
                }
                configureIntent()?.let { b.setConfigureIntent(it) }
                // Do not allowFamily without routes (clearnet fall-through).
                // IPv6 left blocked (no addr/route/DNS) until dual-stack TUN is ready.
                val pfd = b.establish() ?: return null
                runCatching { tun?.close() }
                tun = pfd
                return pfd.fd
            }

            override fun teardownTun() {
                tunSession?.stop()
                tunSession = null
                runCatching { tun?.close() }
                tun = null
            }
        })
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                stopSelf()
                return START_NOT_STICKY
            }
        }
        startForegroundNotification()
        if (starting || (engine?.isRunning == true && tunSession != null)) {
            return START_STICKY
        }
        starting = true
        scope.launch {
            try {
                val eng = engine ?: createEngine().also { attachEngine(it) }
                if (eng.vpnTunnel == null) attachEngine(eng)
                // Establish TUN *before* Tor OR dials so VpnService.protect() works.
                // Do not start userspace packet forwarding until Tor is ready.
                if (useUserspaceTunStack()) {
                    establishTunIface(eng)
                }
                emitStatus(STATUS_BOOTSTRAPPING, "Bootstrapping Tor…")
                eng.start(
                    onReady = {
                        try {
                            if (useUserspaceTunStack()) {
                                startTunSession(eng)
                            }
                            starting = false
                            emitStatus(
                                STATUS_READY,
                                eng.bootstrapLine,
                                socksPort = eng.socksPort,
                                controlPort = eng.controlPort,
                            )
                            onTorReady(eng)
                        } catch (t: Throwable) {
                            starting = false
                            emitStatus(STATUS_ERROR, t.message ?: "TUN start failed")
                            onTorError(t)
                            stopVpn()
                            stopSelf()
                        }
                    },
                    onError = {
                        starting = false
                        emitStatus(STATUS_ERROR, it.message ?: "Tor start failed")
                        onTorError(it)
                        stopVpn()
                        stopSelf()
                    },
                )
            } catch (t: Throwable) {
                starting = false
                emitStatus(STATUS_ERROR, t.message ?: "VPN start failed")
                onTorError(t)
                stopVpn()
                stopSelf()
            }
        }
        return START_STICKY
    }

    private fun establishTunIface(eng: KotlinTorEngine) {
        val tunnel = eng.vpnTunnel ?: error("VPN tunnel not attached")
        tunnel.establishTun() ?: error("VpnService.Builder.establish returned null (consent/revoke?)")
        check(tun != null) { "TUN PFD missing after establish" }
    }

    private fun startTunSession(eng: KotlinTorEngine) {
        val tunnel = eng.vpnTunnel ?: error("VPN tunnel not attached")
        val pfd = tun ?: error("TUN PFD missing — call establishTunIface first")
        if (tunSession != null) return
        val session = VpnTunTorSession(
            scope = scope,
            client = eng.daemonClient(),
            tunPfd = pfd,
            protect = { tunnel.protect(it) },
        )
        tunSession = session
        session.start(torReady = eng.daemonClient().isBootstrapped)
    }

    private fun startForegroundNotification() {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) {
            val ch = NotificationChannel(
                notificationChannelId(),
                "kotlin-tor VPN",
                NotificationManager.IMPORTANCE_LOW,
            )
            nm?.createNotificationChannel(ch)
        }
        val stopPi = PendingIntent.getService(
            this,
            0,
            Intent(this, this::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or pendingImmutable(),
        )
        val notification: Notification = NotificationCompat.Builder(this, notificationChannelId())
            .setContentTitle(sessionName())
            .setContentText("Tor VPN active")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .addAction(0, "Stop", stopPi)
            .setContentIntent(configureIntent())
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(
                notificationId(),
                notification,
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(notificationId(), notification)
        }
    }

    private fun pendingImmutable(): Int =
        if (Build.VERSION.SDK_INT >= 23) PendingIntent.FLAG_IMMUTABLE else 0

    protected fun stopVpn() {
        tunSession?.stop()
        tunSession = null
        engine?.stop()
        engine = null
        runCatching { tun?.close() }
        tun = null
        PlatformNatives.socketProtector = null
        PlatformNatives.socketProtectorSocket = null
        starting = false
        emitStatus(STATUS_STOPPED, "Idle")
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    override fun onRevoke() {
        stopVpn()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn()
        scope.cancel()
        super.onDestroy()
    }

    protected open fun onTorReady(engine: KotlinTorEngine) {}
    protected open fun onTorError(t: Throwable) {}

    protected fun emitStatus(
        state: String,
        message: String,
        socksPort: Int = -1,
        controlPort: Int = -1,
    ) {
        val i = Intent(ACTION_STATUS).setPackage(packageName)
            .putExtra(EXTRA_STATE, state)
            .putExtra(EXTRA_MESSAGE, message)
            .putExtra(EXTRA_SOCKS_PORT, socksPort)
            .putExtra(EXTRA_CONTROL_PORT, controlPort)
        sendBroadcast(i)
    }

    fun currentEngine(): KotlinTorEngine? = engine
    fun tunSession(): VpnTunTorSession? = tunSession

    companion object {
        const val ACTION_STOP = "org.kotlintor.android.VPN_STOP"
        const val ACTION_STATUS = "org.kotlintor.android.VPN_STATUS"
        const val EXTRA_STATE = "state"
        const val EXTRA_MESSAGE = "message"
        const val EXTRA_SOCKS_PORT = "socksPort"
        const val EXTRA_CONTROL_PORT = "controlPort"

        const val STATUS_BOOTSTRAPPING = "bootstrapping"
        const val STATUS_READY = "ready"
        const val STATUS_ERROR = "error"
        const val STATUS_STOPPED = "stopped"

        /** TUN point-to-point address (not in fake-IP cookie space). */
        const val TUN_IPV4 = "10.10.10.1"

        fun vpnEngineConfig(context: Context): TorConfig =
            KotlinTorEngine.routerDefaultConfig(context).copy(
                httpTunnelPort = ListenSpec("127.0.0.1", 0),
                cookieAuthentication = true,
                useMicrodescriptors = false,
                // Fake-IP cookies are IP literals; SafeSocks must allow them under TUN.
                safeSocksAllowIpLiterals = true,
            )
    }
}
