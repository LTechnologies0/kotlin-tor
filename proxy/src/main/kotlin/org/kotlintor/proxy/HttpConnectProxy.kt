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
import org.kotlintor.net.BufferedBytePipe
import org.kotlintor.net.ExitDialer
import org.kotlintor.net.HttpConnectCodec
import org.kotlintor.net.SocketBytePipe
import org.kotlintor.net.StreamRelay
import org.kotlintor.net.StreamShaper
import org.kotlintor.net.negotiateHttpConnect
import org.kotlintor.net.writeHttpConnectSuccess
import java.net.InetSocketAddress
import java.net.ServerSocket

/**
 * HTTP CONNECT tunnel (RFC 9110 §9.3.6) + Tor prop365 isolation / family headers.
 */
class HttpConnectProxy(
    private val dialer: ExitDialer,
    private val scope: CoroutineScope,
    private val optimisticData: Boolean = true,
    private val bytesPerSecond: Long = 0,
    private val maxConcurrent: Int = ProxyAcceptLimits.DEFAULT_TCP,
) {
    constructor(
        client: TorClient,
        scope: CoroutineScope,
        optimisticData: Boolean = true,
        bytesPerSecond: Long = 0,
        maxConcurrent: Int = ProxyAcceptLimits.DEFAULT_TCP,
    ) : this(TorClientDialer(client), scope, optimisticData, bytesPerSecond, maxConcurrent)

    private var job: Job? = null
    private var server: ServerSocket? = null
    private var listenerHandle: ListenerConnection? = null
    private val gate: Semaphore = ProxyAcceptLimits.semaphore(maxConcurrent)

    fun start(listen: ListenSpec) {
        job = scope.launch(Dispatchers.IO) {
            val ss = ServerSocket()
            ss.bind(InetSocketAddress(listen.host, if (listen.port == 0) 0 else listen.port))
            server = ss
            val lh = ConnectionTable.newListener(listen.host, ss.localPort, ConnectionType.AP)
            lh.markOpen()
            listenerHandle = lh
            while (isActive) {
                val sock = runCatching { ss.accept() }.getOrNull() ?: break
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
        val localRaw = SocketBytePipe(socket)
        val local = BufferedBytePipe(
            if (bytesPerSecond > 0) StreamShaper(localRaw, bytesPerSecond) else localRaw,
        )
        try {
            val route = negotiateHttpConnect(
                local,
                optimisticData = optimisticData,
                clientAddr = socket.inetAddress?.hostAddress,
            ) ?: run {
                local.close()
                return
            }
            val remote = try {
                dialer.connect(
                    host = route.endpoint.hostString(),
                    port = route.endpoint.port,
                    isolationKey = route.isolationKey,
                    clientAddr = route.clientAddr,
                    optimisticData = route.optimisticData,
                )
            } catch (_: Exception) {
                local.write(HttpConnectCodec.encodeResponse(502, "Bad Gateway"))
                local.close()
                return
            }
            writeHttpConnectSuccess(local)
            StreamRelay.splice(local, remote)
        } catch (_: Exception) {
            runCatching { local.close() }
        }
    }
}
