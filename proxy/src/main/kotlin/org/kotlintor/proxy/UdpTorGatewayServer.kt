package org.kotlintor.proxy

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.kotlintor.config.ListenSpec
import org.kotlintor.link.ConnectionTable
import org.kotlintor.link.ConnectionType
import org.kotlintor.link.ListenerConnection
import org.kotlintor.net.SocketBytePipe
import org.kotlintor.net.runUdpGateway
import java.net.InetSocketAddress
import java.net.ServerSocket

/**
 * Clearnet (or onion-local) UDP gateway for [org.kotlintor.net.UdpOverTcpFrame].
 * Accept TCP → unpack frames → UDP send/recv → re-frame.
 *
 * Pair with [Socks5Server] `udpTorGateway = host to port` so SOCKS UDP ASSOCIATE
 * rides Tor TCP to this process.
 */
class UdpTorGatewayServer(
    private val scope: CoroutineScope,
) {
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
                launch {
                    try {
                        runUdpGateway(SocketBytePipe(sock))
                    } finally {
                        runCatching { sock.close() }
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
}
