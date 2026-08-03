package org.kotlintor.proxy

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import org.kotlintor.TorClient
import org.kotlintor.config.ListenSpec
import org.kotlintor.link.ConnectionTable
import org.kotlintor.link.ConnectionType
import org.kotlintor.link.ListenerConnection
import org.kotlintor.net.AddrPolicy
import org.kotlintor.net.BufferedBytePipe
import org.kotlintor.net.ExitDialer
import org.kotlintor.net.ProxyKind
import org.kotlintor.net.SocketBytePipe
import org.kotlintor.net.Socks5Outcome
import org.kotlintor.net.Socks5Reply
import org.kotlintor.net.StreamRelay
import org.kotlintor.net.StreamShaper
import org.kotlintor.net.negotiateSocks5
import org.kotlintor.net.socks5BindAccept
import org.kotlintor.net.socks5UdpAssociateRelay
import org.kotlintor.net.socks5UdpAssociateViaTor
import org.kotlintor.net.writeSocks5Failure
import org.kotlintor.net.writeSocks5Success
import java.net.InetSocketAddress
import java.net.ServerSocket

/**
 * SOCKS5(H) proxy (RFC 1928 / 1929) — CONNECT over [ExitDialer]; BIND / UDP ASSOCIATE local
 * (or UDP via Tor TCP gateway when [udpTorGateway] is set).
 */
class Socks5Server(
    private val dialer: ExitDialer,
    private val scope: CoroutineScope,
    private val optimisticData: Boolean = true,
    private val bytesPerSecond: Long = 0,
    private val udpTorGateway: Pair<String, Int>? = null,
    /** SocksPolicy — reject clients whose source addr:port fails the policy. */
    private val clientPolicy: AddrPolicy = AddrPolicy.allowAll(),
    private val maxConcurrent: Int = ProxyAcceptLimits.DEFAULT_TCP,
) {
    constructor(
        client: TorClient,
        scope: CoroutineScope,
        optimisticData: Boolean = true,
        bytesPerSecond: Long = 0,
        udpTorGateway: Pair<String, Int>? = null,
        clientPolicy: AddrPolicy = AddrPolicy.allowAll(),
        maxConcurrent: Int = ProxyAcceptLimits.DEFAULT_TCP,
    ) : this(
        TorClientDialer(client),
        scope,
        optimisticData,
        bytesPerSecond,
        udpTorGateway,
        clientPolicy,
        maxConcurrent,
    )

    private var job: Job? = null
    private var server: ServerSocket? = null
    private var listenerHandle: ListenerConnection? = null
    private val gate: Semaphore = ProxyAcceptLimits.semaphore(maxConcurrent)

    fun start(listen: ListenSpec) {
        val ss = ServerSocket()
        ss.bind(InetSocketAddress(listen.host, if (listen.port == 0) 0 else listen.port))
        server = ss
        val lh = ConnectionTable.newListener(listen.host, ss.localPort, ConnectionType.AP)
        lh.markOpen()
        listenerHandle = lh
        job = scope.launch(Dispatchers.IO) {
            while (isActive) {
                val sock = runCatching { ss.accept() }.getOrNull() ?: break
                val peer = sock.inetAddress
                val peerPort = sock.port
                if (peer != null && !clientPolicy.allows(peer, peerPort)) {
                    runCatching { sock.close() }
                    continue
                }
                if (!gate.tryAcquire()) {
                    runCatching { sock.close() }
                    continue
                }
                launch {
                    try {
                        handle(sock)
                    } finally {
                        gate.release()
                    }
                }
            }
        }
    }

    fun boundPort(): Int = server?.localPort ?: -1

    fun stop() {
        runCatching { server?.close() }
        job?.cancel()
        listenerHandle?.let {
            it.markClosed()
            ConnectionTable.remove(it.id)
        }
        listenerHandle = null
    }

    private suspend fun handle(socket: java.net.Socket) {
        val peerHost = socket.inetAddress?.hostAddress ?: "0.0.0.0"
        val peerPort = socket.port
        val entry = ConnectionTable.newEntry(
            peerHost,
            peerPort,
            socksUser = null,
            isolationKey = null,
        )
        entry.markOpen()
        val localRaw = SocketBytePipe(socket)
        val local = BufferedBytePipe(
            if (bytesPerSecond > 0) StreamShaper(localRaw, bytesPerSecond) else localRaw,
        )
        try {
            when (
                val outcome = negotiateSocks5(
                    local,
                    optimisticData = optimisticData,
                    clientAddr = peerHost,
                )
            ) {
                null -> {
                    local.close()
                    return
                }
                is Socks5Outcome.Connect -> {
                    val route = outcome.route
                    check(route.via == ProxyKind.Socks5)
                    entry.originalDest = "${route.endpoint.hostString()}:${route.endpoint.port}"
                    // Linked AP↔EXIT pair for local accounting (exit handle tracks dest).
                    val exit = ConnectionTable.newExit(
                        route.endpoint.hostString(),
                        route.endpoint.port,
                        streamId = 0,
                        circId = 0,
                    )
                    exit.markOpen()
                    entry.linkTo(exit)
                    val remote = try {
                        dialer.connect(
                            host = route.endpoint.hostString(),
                            port = route.endpoint.port,
                            isolationKey = route.isolationKey,
                            clientAddr = route.clientAddr,
                            optimisticData = route.optimisticData,
                        )
                    } catch (e: Exception) {
                        System.err.println(
                            "SOCKS connect ${route.endpoint.hostString()}:${route.endpoint.port} failed: ${e.message}",
                        )
                        writeSocks5Failure(local, Socks5Reply.HostUnreachable)
                        local.close()
                        exit.markClosed()
                        ConnectionTable.remove(exit.id)
                        return
                    }
                    writeSocks5Success(local)
                    try {
                        StreamRelay.splice(local, remote)
                    } finally {
                        exit.markClosed()
                        ConnectionTable.remove(exit.id)
                    }
                }
                is Socks5Outcome.Bind -> {
                    val peer = socks5BindAccept(local) ?: run {
                        local.close()
                        return
                    }
                    StreamRelay.splice(local, SocketBytePipe(peer))
                }
                is Socks5Outcome.UdpAssociate -> {
                    val gw = udpTorGateway
                    if (gw != null) {
                        val tor = dialer.connect(
                            host = gw.first,
                            port = gw.second,
                            isolationKey = outcome.isolationKey ?: "udp-assoc",
                            clientAddr = outcome.clientAddr,
                        )
                        socks5UdpAssociateViaTor(local, outcome.clientHint, tor)
                    } else {
                        socks5UdpAssociateRelay(local, outcome.clientHint)
                    }
                    local.close()
                }
            }
        } catch (_: Exception) {
            runCatching { local.close() }
        } finally {
            entry.markClosed()
            ConnectionTable.remove(entry.id)
        }
    }
}
