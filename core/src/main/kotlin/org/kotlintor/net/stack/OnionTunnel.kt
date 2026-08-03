package org.kotlintor.net.stack

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.kotlintor.TorClient
import org.kotlintor.net.BytePipe
import org.kotlintor.net.TorStreamBytePipe
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Onionmasq-class NI façade over [TunTorBridge] / [TunIpStack] (pure Kotlin).
 *
 * TCP SYN → reverse fake-IP cookie → [TorClient.connect]; UDP DNS → [TunFakeDns];
 * other UDP dropped. Scaffolding drives protect / isolation / commands.
 */
class OnionTunnel(
    private val scope: CoroutineScope,
    private val io: PacketIo,
    private val client: TorClient,
    private val scaffolding: OnionTunnelScaffolding = DefaultOnionTunnelScaffolding(),
    private val mtu: Int = 1500,
    val dns: TunFakeDns = TunFakeDns(),
) {
    private val bridge: TunTorBridge
    private var commandJob: Job? = null
    private val running = AtomicBoolean(false)
    private val bytesUp = AtomicLong(0)
    private val bytesDown = AtomicLong(0)
    private val ready = AtomicBoolean(false)

    val cookies: FakeIpDnsCookies get() = dns.cookies
    val ipStack: TunIpStack get() = bridge.ipStack
    val isRunning: Boolean get() = running.get()
    val isReady: Boolean get() = ready.get()
    fun bandwidthUp(): Long = bytesUp.get()
    fun bandwidthDown(): Long = bytesDown.get()

    init {
        bridge = TunTorBridge(
            scope = scope,
            io = io,
            openTcp = { dstIp, dstPort -> openTcpFlow(dstIp, dstPort) },
            onUdp = { srcIp, srcPort, dstIp, dstPort, payload ->
                handleUdp(srcIp, srcPort, dstIp, dstPort, payload)
            },
            mtu = mtu,
        )
    }

    /**
     * Mark Tor usable and fire [OnionTunnelScaffolding.onBootstrapped].
     * Call after bootstrap / protect attached — gates app TCP until set.
     */
    fun markBootstrapped() {
        ready.set(true)
        scaffolding.onBootstrapped()
    }

    fun start() {
        if (!running.compareAndSet(false, true)) return
        bridge.start()
        commandJob = scope.launch {
            val flow = scaffolding.commandStream() ?: return@launch
            flow.collect { cmd -> handleCommand(cmd) }
        }
    }

    fun stop() {
        if (!running.getAndSet(false)) return
        commandJob?.cancel()
        commandJob = null
        bridge.stop()
        ready.set(false)
    }

    private suspend fun openTcpFlow(dstIp: String, dstPort: Int): BytePipe {
        if (!ready.get()) {
            error("OnionTunnel not bootstrapped")
        }
        val scaffoldingLocal = scaffolding
        if (scaffoldingLocal is DefaultOnionTunnelScaffolding && scaffoldingLocal.dormant) {
            error("OnionTunnel dormant")
        }
        val hostname = cookies.reverse(dstIp) ?: dstIp
        val src = InetSocketAddress(InetAddress.getByName("0.0.0.0"), 0)
        val dst = InetSocketAddress(
            runCatching { InetAddress.getByName(dstIp) }.getOrElse { InetAddress.getByName("0.0.0.0") },
            dstPort,
        )
        val isolationKey = scaffolding.isolate(src, dst, PROTO_TCP)
        if (scaffolding.requireProtectAttached() &&
            org.kotlintor.os.PlatformNatives.socketProtector == null
        ) {
            error("VPN protect not attached before OR dial")
        }
        val isolationStr = "vpn-tun|$isolationKey|$hostname|$dstPort"
        return try {
            val stream = client.connect(hostname, dstPort, isolationKey = isolationStr)
            scaffolding.onEstablished(isolationKey, hostname, dstPort)
            val inner = TorStreamBytePipe(stream)
            object : BytePipe by inner {
                override suspend fun read(dst: ByteArray, offset: Int, length: Int): Int {
                    val n = inner.read(dst, offset, length)
                    if (n > 0) bytesDown.addAndGet(n.toLong())
                    return n
                }
                override suspend fun write(src: ByteArray, offset: Int, length: Int) {
                    bytesUp.addAndGet(length.toLong())
                    inner.write(src, offset, length)
                }
                override suspend fun close() {
                    runCatching { inner.close() }
                    scaffolding.onSocketClose(isolationKey)
                }
            }
        } catch (t: Throwable) {
            scaffolding.onFailure(isolationKey, hostname, dstPort, t)
            throw t
        }
    }

    private suspend fun handleUdp(
        srcIp: ByteArray,
        srcPort: Int,
        dstIp: ByteArray,
        dstPort: Int,
        payload: ByteArray,
    ) {
        if (!TunFakeDns.isDnsPort(dstPort)) {
            // First ship: reject non-DNS UDP (no TURN).
            return
        }
        if (!TunFakeDns.isFakeResolver(dstIp) && !TunFakeDns.isDnsPort(dstPort)) return
        val src = InetSocketAddress(
            InetAddress.getByAddress(srcIp),
            srcPort,
        )
        val dst = InetSocketAddress(
            InetAddress.getByAddress(dstIp),
            dstPort,
        )
        val isolationKey = scaffolding.isolate(src, dst, PROTO_UDP)
        val reply = dns.handleQuery(payload, isolationKey) ?: return
        bridge.ipStack.sendUdp(
            srcIp = dstIp,
            srcPort = dstPort,
            dstIp = srcIp,
            dstPort = srcPort,
            payload = reply,
        )
    }

    private suspend fun handleCommand(cmd: OnionTunnelCommand) {
        when (cmd) {
            OnionTunnelCommand.RefreshCircuits -> {
                runCatching { client.refreshCircuits() }
            }
            is OnionTunnelCommand.RefreshCircuitsForApp -> {
                runCatching { client.refreshCircuits() }
            }
            is OnionTunnelCommand.SetDormant -> {
                val s = scaffolding
                if (s is DefaultOnionTunnelScaffolding) {
                    s.applyDormant(cmd.dormant)
                }
                // Polarity: dormant=true means pause new circuits (onionmasq Soft mapping hazard).
                runCatching {
                    if (cmd.dormant) client.setDormant(true) else client.setDormant(false)
                }
            }
        }
    }

    companion object {
        const val PROTO_TCP = 6
        const val PROTO_UDP = 17

        /** Build a tunnel over [MemoryTun] for unit tests. */
        fun withMemoryTun(
            scope: CoroutineScope,
            client: TorClient,
            scaffolding: OnionTunnelScaffolding = DefaultOnionTunnelScaffolding(),
            tun: MemoryTun = MemoryTun(),
        ): Pair<OnionTunnel, MemoryTun> {
            val tunnel = OnionTunnel(scope, tun, client, scaffolding)
            return tunnel to tun
        }
    }
}
