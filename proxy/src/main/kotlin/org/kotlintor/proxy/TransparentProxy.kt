package org.kotlintor.proxy

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withContext
import org.kotlintor.TorClient
import org.kotlintor.config.ListenSpec
import org.kotlintor.link.ConnectionTable
import org.kotlintor.link.ConnectionType
import org.kotlintor.link.ListenerConnection
import org.kotlintor.net.ExitDialer
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

/**
 * TransPort (transparent proxy): accept redirected TCP and BEGIN to original destination.
 *
 * [originalDst] resolves SO_ORIGINAL_DST (Linux iptables REDIRECT) when provided;
 * otherwise reads a 6-byte big-endian IPv4+port prefix (test / userspace helper).
 */
class TransparentProxy(
    private val dialer: ExitDialer,
    private val scope: CoroutineScope,
    private val maxConcurrent: Int = ProxyAcceptLimits.DEFAULT_TCP,
    private val originalDst: (Socket) -> Pair<String, Int>? = { LinuxOriginalDst.resolve(it) },
) {
    constructor(
        client: TorClient,
        scope: CoroutineScope,
        maxConcurrent: Int = ProxyAcceptLimits.DEFAULT_TCP,
        originalDst: (Socket) -> Pair<String, Int>? = { LinuxOriginalDst.resolve(it) },
    ) : this(TorClientDialer(client), scope, maxConcurrent, originalDst)

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

    private suspend fun handle(socket: Socket) = withContext(Dispatchers.IO) {
        val peerHost = socket.inetAddress?.hostAddress ?: "0.0.0.0"
        val entry = ConnectionTable.newEntry(peerHost, socket.port)
        entry.markOpen()
        try {
            val dst = originalDst(socket) ?: readPrefixedDst(socket)
            if (dst == null) {
                socket.close()
                return@withContext
            }
            val (host, port) = dst
            entry.originalDest = "$host:$port"
            val exit = ConnectionTable.newExit(host, port, streamId = 0, circId = 0)
            exit.markOpen()
            entry.linkTo(exit)
            try {
                val stream = dialer.connect(host, port, clientAddr = peerHost)
                val up = launch {
                    val buf = ByteArray(16 * 1024)
                    while (isActive) {
                        val n = socket.getInputStream().read(buf)
                        if (n < 0) break
                        stream.write(buf, 0, n)
                    }
                    runCatching { stream.close() }
                }
                try {
                    val buf = ByteArray(16 * 1024)
                    while (isActive) {
                        val n = stream.read(buf)
                        if (n < 0) break
                        if (n == 0) continue
                        socket.getOutputStream().write(buf, 0, n)
                        socket.getOutputStream().flush()
                    }
                } finally {
                    up.cancel()
                    runCatching { stream.close() }
                    runCatching { socket.close() }
                }
            } finally {
                exit.markClosed()
                ConnectionTable.remove(exit.id)
            }
        } catch (_: Exception) {
            runCatching { socket.close() }
        } finally {
            entry.markClosed()
            ConnectionTable.remove(entry.id)
        }
    }

    /** Test helper: first 6 bytes = IPv4 (4) + port u16 BE. */
    private fun readPrefixedDst(socket: Socket): Pair<String, Int>? {
        val hdr = ByteArray(6)
        val input = socket.getInputStream()
        var off = 0
        while (off < 6) {
            val n = input.read(hdr, off, 6 - off)
            if (n <= 0) return null
            off += n
        }
        val host = "${hdr[0].toInt() and 0xff}.${hdr[1].toInt() and 0xff}." +
            "${hdr[2].toInt() and 0xff}.${hdr[3].toInt() and 0xff}"
        val port = ((hdr[4].toInt() and 0xff) shl 8) or (hdr[5].toInt() and 0xff)
        return host to port
    }
}
