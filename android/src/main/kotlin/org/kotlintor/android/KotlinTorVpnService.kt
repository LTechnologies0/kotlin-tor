package org.kotlintor.android

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.kotlintor.net.stack.FakeIpDnsCookies

/**
 * VpnService base for OnionVPN-style TUN capture + Tor SOCKS handoff.
 *
 * Subclasses call [Builder] to establish the TUN, then [attachEngine] so
 * kotlin-tor protects uplink sockets via [VpnService.protect] **before** bootstrap OR dials.
 * When [useUserspaceTunStack] is true, TUN packets go through [OnionTunnel].
 */
abstract class KotlinTorVpnService : VpnService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var engine: KotlinTorEngine? = null
    private var tun: ParcelFileDescriptor? = null
    private var tunSession: VpnTunTorSession? = null

    protected open fun createEngine(): KotlinTorEngine =
        KotlinTorEngine(applicationContext)

    /** When true (default), TUN packets go through [OnionTunnel] / userspace IP stack. */
    protected open fun useUserspaceTunStack(): Boolean = true

    fun attachEngine(eng: KotlinTorEngine = createEngine()) {
        engine = eng
        // Bootstrap gate: install protect **before** eng.start() OR dials.
        eng.attachVpn(object : VpnTunnel {
            override fun protect(fd: Int): Boolean =
                this@KotlinTorVpnService.protect(fd)
            override fun establishTun(mtu: Int): Int? {
                val b = Builder()
                    .setSession("kotlin-tor")
                    .setMtu(mtu)
                    .addAddress("10.10.10.1", 32)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer(FakeIpDnsCookies.FAKE_RESOLVER_V4)
                val pfd = b.establish() ?: return null
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
        scope.launch {
            val eng = engine ?: createEngine().also { attachEngine(it) }
            // Re-attach if engine was created without VPN (protect before start).
            if (eng.vpnTunnel == null) attachEngine(eng)
            eng.start(
                onReady = {
                    if (useUserspaceTunStack()) {
                        startTunStack(eng)
                    }
                    onTorReady(eng)
                },
                onError = { onTorError(it) },
            )
        }
        return START_STICKY
    }

    private fun startTunStack(eng: KotlinTorEngine) {
        val tunnel = eng.vpnTunnel ?: return
        tunnel.establishTun() ?: return
        val pfd = tun ?: return
        val session = VpnTunTorSession(
            scope = scope,
            client = eng.daemonClient(),
            tunPfd = pfd,
            protect = { tunnel.protect(it) },
        )
        tunSession = session
        session.start()
    }

    override fun onDestroy() {
        tunSession?.stop()
        tunSession = null
        engine?.stop()
        runCatching { tun?.close() }
        scope.cancel()
        super.onDestroy()
    }

    protected open fun onTorReady(engine: KotlinTorEngine) {}
    protected open fun onTorError(t: Throwable) {}
}
