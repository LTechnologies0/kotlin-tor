package org.kotlintor.proxy

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.kotlintor.TorClient
import org.kotlintor.config.ListenSpec
import org.kotlintor.link.ConnectionTable
import org.kotlintor.link.ConnectionType
import org.kotlintor.link.ListenerConnection
import org.kotlintor.net.BufferedBytePipe
import org.kotlintor.net.ExitDialer
import org.kotlintor.net.HttpConnectCodec
import org.kotlintor.net.HttpProxyCodec
import org.kotlintor.net.LocalProxyOutcome
import org.kotlintor.net.ProxyKind
import org.kotlintor.net.SocketBytePipe
import org.kotlintor.net.Socks4Codec
import org.kotlintor.net.Socks5Reply
import org.kotlintor.net.StreamRelay
import org.kotlintor.net.StreamShaper
import org.kotlintor.net.negotiateMultilingual
import org.kotlintor.net.writeHttpConnectSuccess
import org.kotlintor.net.writeSocks4Success
import org.kotlintor.net.writeSocks5Failure
import org.kotlintor.net.writeSocks5Success
import java.net.InetSocketAddress
import java.net.ServerSocket

/**
 * Multilingual proxy port: SOCKS4/5, HTTP CONNECT/OPTIONS/absolute-form, TLS SNI peek (prop365+).
 */
class BilingualProxyServer(
    private val dialer: ExitDialer,
    private val scope: CoroutineScope,
    private val optimisticData: Boolean = true,
    private val bytesPerSecond: Long = 0,
) {
    constructor(
        client: TorClient,
        scope: CoroutineScope,
        optimisticData: Boolean = true,
        bytesPerSecond: Long = 0,
    ) : this(TorClientDialer(client), scope, optimisticData, bytesPerSecond)

    private var job: Job? = null
    private var server: ServerSocket? = null
    private var listenerHandle: ListenerConnection? = null

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
                launch { handle(sock) }
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
            when (
                val outcome = negotiateMultilingual(
                    local,
                    optimisticData = optimisticData,
                    clientAddr = socket.inetAddress?.hostAddress,
                )
            ) {
                null -> {
                    local.close()
                    return
                }
                is LocalProxyOutcome.Done -> {
                    local.close()
                    return
                }
                is LocalProxyOutcome.Route -> {
                    val route = outcome.route
                    val remote = try {
                        dialer.connect(
                            host = route.endpoint.hostString(),
                            port = route.endpoint.port,
                            isolationKey = route.isolationKey,
                            clientAddr = route.clientAddr,
                            optimisticData = route.optimisticData,
                        )
                    } catch (_: Exception) {
                        when (route.via) {
                            ProxyKind.Socks5 -> writeSocks5Failure(local, Socks5Reply.HostUnreachable)
                            ProxyKind.Socks4 -> local.write(Socks4Codec.encodeReply(Socks4Codec.REP_REJECTED))
                            ProxyKind.HttpConnect, ProxyKind.HttpAbsolute ->
                                local.write(
                                    HttpConnectCodec.encodeResponse(
                                        502,
                                        "Bad Gateway",
                                        HttpProxyCodec.torResponseHeaders(),
                                    ),
                                )
                            else -> Unit
                        }
                        local.close()
                        return
                    }
                    when (route.via) {
                        ProxyKind.Socks5 -> writeSocks5Success(local)
                        ProxyKind.Socks4 -> writeSocks4Success(local)
                        ProxyKind.HttpConnect -> writeHttpConnectSuccess(local)
                        ProxyKind.HttpAbsolute, ProxyKind.TlsSni -> Unit
                        else -> Unit
                    }
                    if (outcome.prelude.isNotEmpty()) {
                        remote.write(outcome.prelude)
                    }
                    StreamRelay.splice(local, remote)
                }
            }
        } catch (_: Exception) {
            runCatching { local.close() }
        }
    }
}
