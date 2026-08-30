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
import org.kotlintor.net.ProtocolPeek
import org.kotlintor.net.SocketBytePipe
import org.kotlintor.net.StreamRelay
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

/**
 * Fixed-destination tunnel with optional [ProtocolPeek] logging.
 */
class FixedTorTunnel(
    private val dialer: ExitDialer,
    private val scope: CoroutineScope,
    private val remoteHost: String,
    private val remotePort: Int,
    private val isolationPrefix: String = "app",
    private val peekBytes: Int = 16,
    private val onPeek: ((ProtocolPeek.Kind) -> Unit)? = null,
    private val maxConcurrent: Int = ProxyAcceptLimits.DEFAULT_TCP,
) {
    constructor(
        client: TorClient,
        scope: CoroutineScope,
        remoteHost: String,
        remotePort: Int,
        isolationPrefix: String = "app",
        peekBytes: Int = 16,
        onPeek: ((ProtocolPeek.Kind) -> Unit)? = null,
        maxConcurrent: Int = ProxyAcceptLimits.DEFAULT_TCP,
    ) : this(
        TorClientDialer(client),
        scope,
        remoteHost,
        remotePort,
        isolationPrefix,
        peekBytes,
        onPeek,
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

    private suspend fun handle(socket: Socket) {
        val local = BufferedBytePipe(SocketBytePipe(socket))
        try {
            if (onPeek != null && peekBytes > 0) {
                val peek = local.readFully(peekBytes.coerceAtMost(64))
                onPeek.invoke(ProtocolPeek.classify(peek))
                local.pushFront(peek)
            }
            val remote = dialer.connect(
                remoteHost,
                remotePort,
                isolationKey = "$isolationPrefix|$remoteHost|$remotePort",
            )
            try {
                StreamRelay.splice(local, remote)
            } finally {
                runCatching { remote.close() }
            }
        } finally {
            runCatching { local.close() }
        }
    }
}
