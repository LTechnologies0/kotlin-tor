package org.kotlintor.proxy

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withContext
import org.kotlintor.TorClient
import org.kotlintor.config.ListenSpec
import org.kotlintor.link.ConnectionTable
import org.kotlintor.link.ConnectionType
import org.kotlintor.link.ListenerConnection
import org.kotlintor.net.BufferedBytePipe
import org.kotlintor.net.ExitDialer
import org.kotlintor.net.FtpControlFilter
import org.kotlintor.net.FtpTorRewrite
import org.kotlintor.net.LineReader
import org.kotlintor.net.SocketBytePipe
import org.kotlintor.net.StreamRelay
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap

/**
 * FTP control proxy with PASV/PORT rewrite (RFC 959 / 2428) over [ExitDialer].
 */
class FtpTorProxy(
    private val dialer: ExitDialer,
    private val scope: CoroutineScope,
    private val remoteHost: String,
    private val remotePort: Int = 21,
    private val advertiseHost: String = "127.0.0.1",
    private val maxConcurrent: Int = ProxyAcceptLimits.DEFAULT_TCP,
) {
    constructor(
        client: TorClient,
        scope: CoroutineScope,
        remoteHost: String,
        remotePort: Int = 21,
        advertiseHost: String = "127.0.0.1",
        maxConcurrent: Int = ProxyAcceptLimits.DEFAULT_TCP,
    ) : this(TorClientDialer(client), scope, remoteHost, remotePort, advertiseHost, maxConcurrent)

    private var job: Job? = null
    private var server: ServerSocket? = null
    private var listenerHandle: ListenerConnection? = null
    private val reservedListens = ConcurrentHashMap<Int, ServerSocket>()
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
                        handleControl(sock)
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
        reservedListens.values.forEach { runCatching { it.close() } }
        reservedListens.clear()
        job?.cancel()
        listenerHandle?.let {
            it.markClosed()
            ConnectionTable.remove(it.id)
        }
        listenerHandle = null
    }

    private fun reservePort(): Int {
        val ss = ServerSocket()
        ss.bind(InetSocketAddress(advertiseHost, 0))
        reservedListens[ss.localPort] = ss
        return ss.localPort
    }

    private suspend fun handleControl(socket: Socket) {
        val local = BufferedBytePipe(SocketBytePipe(socket))
        val torStream = dialer.connect(remoteHost, remotePort, isolationKey = "ftp|$remoteHost|$remotePort")
        val remote = BufferedBytePipe(torStream)
        val pending = ArrayList<FtpTorRewrite.DataChannelNeed>()
        val filter = FtpControlFilter(
            advertiseHost = advertiseHost,
            allocateLocalPort = { reservePort() },
            remoteHostHint = remoteHost,
            onDataChannel = { pending += it },
        )
        try {
            val localReader = LineReader(local)
            val remoteReader = LineReader(remote)
            val greeting = remoteReader.readLine() ?: return
            localReader.writeLine(filter.filterServerToClient(greeting))
            drainPending(pending)

            coroutineScope {
                val up = launch {
                    while (true) {
                        val line = localReader.readLine() ?: break
                        remoteReader.writeLine(filter.filterClientToServer(line))
                        drainPending(pending)
                    }
                }
                try {
                    while (true) {
                        val line = remoteReader.readLine() ?: break
                        localReader.writeLine(filter.filterServerToClient(line))
                        drainPending(pending)
                    }
                } finally {
                    up.cancel()
                }
            }
        } finally {
            runCatching { local.close() }
            runCatching { remote.close() }
            runCatching { torStream.close() }
        }
    }

    private fun drainPending(pending: MutableList<FtpTorRewrite.DataChannelNeed>) {
        while (pending.isNotEmpty()) {
            val need = pending.removeAt(0)
            scope.launch(Dispatchers.IO) { armDataChannel(need) }
        }
    }

    private suspend fun armDataChannel(need: FtpTorRewrite.DataChannelNeed) {
        val ss = reservedListens.remove(need.advertise.port)
            ?: ServerSocket().also { it.bind(InetSocketAddress(advertiseHost, need.advertise.port)) }
        try {
            ss.soTimeout = 120_000
            val peer = withContext(Dispatchers.IO) { ss.accept() }
            val dial = need.torDial ?: return
            val tor = dialer.connect(
                host = dial.hostString(),
                port = dial.port,
                isolationKey = "ftp-data|${dial.hostString()}|${dial.port}",
            )
            try {
                StreamRelay.splice(SocketBytePipe(peer), tor)
            } finally {
                runCatching { peer.close() }
                runCatching { tor.close() }
            }
        } finally {
            runCatching { ss.close() }
        }
    }
}
