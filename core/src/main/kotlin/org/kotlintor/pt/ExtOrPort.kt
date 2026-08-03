package org.kotlintor.pt

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.kotlintor.config.TorConfig
import org.kotlintor.link.ConnectionTable
import org.kotlintor.link.ConnectionType
import org.kotlintor.link.ExtOrConnectionHandle
import org.kotlintor.link.ListenerConnection
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.nio.charset.StandardCharsets

/**
 * ExtORPort (extended ORPort) for pluggable transports (pt-spec).
 * Accepts USERADDR / TRANSPORT commands then hands the socket to the OR.
 */
class ExtOrPortServer(
    private val config: TorConfig,
    private val scope: CoroutineScope,
    private val onClient: (java.net.Socket, userAddr: String?, transport: String?) -> Unit = { s, _, _ -> s.close() },
) {
    private var job: Job? = null
    private var server: ServerSocket? = null
    private var listenerHandle: ListenerConnection? = null

    fun start() {
        val port = config.extOrPort ?: return
        job = scope.launch(Dispatchers.IO) {
            val ss = ServerSocket()
            ss.bind(InetSocketAddress(port.host, port.port))
            server = ss
            val lh = ConnectionTable.newListener(port.host, ss.localPort, ConnectionType.EXT_OR)
            lh.markOpen()
            listenerHandle = lh
            println("ExtORPort ${port.host}:${ss.localPort}")
            while (isActive) {
                val sock = runCatching { ss.accept() }.getOrNull() ?: break
                launch(Dispatchers.IO) { handle(sock) }
            }
        }
    }

    fun boundPort(): Int = server?.localPort ?: -1

    private fun handle(socket: java.net.Socket) {
        val peerHost = socket.inetAddress?.hostAddress ?: "0.0.0.0"
        val extHandle: ExtOrConnectionHandle = ConnectionTable.newExtOr(peerHost, socket.port)
        extHandle.markOpen()
        try {
            socket.soTimeout = 30_000
            val reader = BufferedReader(InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII))
            val writer = OutputStreamWriter(socket.getOutputStream(), StandardCharsets.US_ASCII)
            var userAddr: String? = null
            var transport: String? = null
            while (true) {
                val line = reader.readLine() ?: break
                when {
                    line.startsWith("USERADDR ") -> {
                        userAddr = line.removePrefix("USERADDR ").trim()
                        extHandle.userId = userAddr
                        writer.write("250 OK\n"); writer.flush()
                    }
                    line.startsWith("TRANSPORT ") -> {
                        transport = line.removePrefix("TRANSPORT ").trim()
                        extHandle.transportName = transport
                        writer.write("250 OK\n"); writer.flush()
                    }
                    line == "DONE" -> {
                        writer.write("250 OK\n"); writer.flush()
                        onClient(socket, userAddr, transport)
                        return
                    }
                    else -> {
                        writer.write("510 Unrecognized\n"); writer.flush()
                    }
                }
            }
            socket.close()
        } catch (_: Exception) {
            runCatching { socket.close() }
        } finally {
            extHandle.markClosed()
            ConnectionTable.remove(extHandle.id)
        }
    }

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
