package org.kotlintor.relay

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.kotlintor.config.ListenSpec
import org.kotlintor.config.TorConfig
import java.io.BufferedOutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicLong

/**
 * MetricsPort (torrc) — Prometheus-ish text exposition for process/relay counters.
 */
class MetricsPortServer(
    private val config: TorConfig,
    private val scope: CoroutineScope,
    private val identityHex: () -> String = { "unknown" },
    private val counters: MetricsCounters = MetricsCounters(),
) {
    private var job: Job? = null
    private var server: ServerSocket? = null
    private var listenerHandle: org.kotlintor.link.ListenerConnection? = null

    fun start(listen: ListenSpec) {
        job = scope.launch(Dispatchers.IO) {
            val ss = ServerSocket()
            ss.bind(InetSocketAddress(listen.host, if (listen.port == 0) 0 else listen.port))
            server = ss
            val lh = org.kotlintor.link.ConnectionTable.newListener(
                listen.host,
                ss.localPort,
                org.kotlintor.link.ConnectionType.AP, // metrics is app-facing listen
            )
            // Prefer DIR-like listen typing for metrics (no dedicated type); use LISTENER+AP.
            lh.markOpen()
            listenerHandle = lh
            println("MetricsPort ${listen.host}:${ss.localPort}")
            while (isActive) {
                val sock = runCatching { ss.accept() }.getOrNull() ?: break
                launch(Dispatchers.IO) {
                    try {
                        val req = sock.getInputStream().readNBytes(4096).toString(StandardCharsets.US_ASCII)
                        val body = if (req.startsWith("GET ")) render() else "Bad Request\n"
                        val status = if (req.startsWith("GET ")) "200 OK" else "400 Bad Request"
                        val bytes = body.toByteArray(StandardCharsets.UTF_8)
                        val out = BufferedOutputStream(sock.getOutputStream())
                        out.write(
                            ("HTTP/1.0 $status\r\nContent-Type: text/plain; version=0.0.4\r\n" +
                                "Content-Length: ${bytes.size}\r\n\r\n").toByteArray(StandardCharsets.US_ASCII),
                        )
                        out.write(bytes)
                        out.flush()
                    } catch (_: Exception) {
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
            org.kotlintor.link.ConnectionTable.remove(it.id)
        }
        listenerHandle = null
    }

    fun counters(): MetricsCounters = counters

    private fun render(): String = buildString {
        append("# HELP ktor_info kotlin-tor process info\n")
        append("# TYPE ktor_info gauge\n")
        append("ktor_info{version=\"0.1.0\",identity=\"${identityHex()}\"} 1\n")
        append("# HELP ktor_circuits_created_total Circuits created on ORPort\n")
        append("# TYPE ktor_circuits_created_total counter\n")
        append("ktor_circuits_created_total ${counters.circuitsCreated.get()}\n")
        append("# HELP ktor_bytes_read_total Bytes read on ORPort\n")
        append("# TYPE ktor_bytes_read_total counter\n")
        append("ktor_bytes_read_total ${counters.bytesRead.get()}\n")
        append("# HELP ktor_bytes_written_total Bytes written on ORPort\n")
        append("# TYPE ktor_bytes_written_total counter\n")
        append("ktor_bytes_written_total ${counters.bytesWritten.get()}\n")
        append("# HELP ktor_uptime_seconds Process uptime\n")
        append("# TYPE ktor_uptime_seconds gauge\n")
        append("ktor_uptime_seconds ${(System.currentTimeMillis() - counters.startedAtMs) / 1000.0}\n")
    }
}

class MetricsCounters {
    val startedAtMs: Long = System.currentTimeMillis()
    val circuitsCreated = AtomicLong(0)
    val bytesRead = AtomicLong(0)
    val bytesWritten = AtomicLong(0)
}
