package org.kotlintor.demo

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL

/**
 * Feature actions for demo UIs, backed by [DemoSession].
 */
class DemoFeatures(private val session: DemoSession) {

    fun requireDaemon() =
        session.torDaemon ?: error("Demo session not running")

    suspend fun newnym() {
        val d = requireDaemon()
        d.signalNewnym()
        DemoLogBuffer.append("ui", "NEWNYM")
    }

    fun setDormant(value: Boolean) {
        requireDaemon().client.setDormant(value)
        DemoLogBuffer.append("circ", "dormant=$value")
    }

    fun circuitStatusLines(): List<String> =
        session.torDaemon?.client?.circuitStatusLines().orEmpty()

    fun guardStatusLines(): List<String> =
        session.torDaemon?.client?.sampledGuardStatusLines().orEmpty()

    /** One-line engine honesty banner for Overview panels. */
    fun engineHonestyNote(): String = DemoEngineStatus.HONESTY_NOTE

    suspend fun socksSelfCheck(): String = withContext(Dispatchers.IO) {
        val port = session.ports().socks
        if (port <= 0) return@withContext "No SOCKS port"
        httpGet(
            "https://check.torproject.org/api/ip",
            Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port)),
        )
    }

    suspend fun resolve(hostname: String): String = withContext(Dispatchers.IO) {
        val host = hostname.trim()
        if (host.isEmpty()) return@withContext "Enter a hostname"
        runCatching { requireDaemon().client.resolve(host) }
            .fold(
                onSuccess = { ips ->
                    if (ips.isEmpty()) "Empty result (rejected/NX)"
                    else ips.joinToString("\n")
                },
                onFailure = { t -> "Fail: ${t.javaClass.simpleName}: ${t.message}" },
            )
    }

    suspend fun fetchOnionDescriptor(onionAddress: String): String = withContext(Dispatchers.IO) {
        var onion = onionAddress.trim()
        if (onion.isEmpty()) return@withContext "Enter a .onion address"
        if (!onion.endsWith(".onion", ignoreCase = true)) onion = "$onion.onion"
        runCatching {
            val doc = requireDaemon().client.fetchOnionDescriptor(onion)
            "OK ${doc.length} bytes\n" + doc.take(1_200) + if (doc.length > 1_200) "\n…" else ""
        }.fold(
            onSuccess = { it },
            onFailure = { t -> "Fail: ${t.javaClass.simpleName}: ${t.message}" },
        )
    }

    suspend fun controlGetInfo(): String = withContext(Dispatchers.IO) {
        val d = requireDaemon()
        val port = session.ports().control
        if (port <= 0) return@withContext "No control port"
        runCatching {
            DemoControlClient.getInfo(
                "127.0.0.1",
                port,
                d.controlCookiePath,
                listOf("version", "status/bootstrap-phase"),
            )
        }.fold(
            onSuccess = { it },
            onFailure = { t -> "Fail: ${t.javaClass.simpleName}: ${t.message}" },
        )
    }

    suspend fun controlSignal(signal: String): String = withContext(Dispatchers.IO) {
        val d = requireDaemon()
        val port = session.ports().control
        if (port <= 0) return@withContext "No control port"
        runCatching {
            DemoControlClient.signal("127.0.0.1", port, d.controlCookiePath, signal)
        }.fold(
            onSuccess = { it },
            onFailure = { t -> "Fail: ${t.javaClass.simpleName}: ${t.message}" },
        )
    }

    companion object {
        fun httpGet(url: String, proxy: Proxy): String =
            runCatching {
                val conn = URL(url).openConnection(proxy) as HttpURLConnection
                conn.connectTimeout = 45_000
                conn.readTimeout = 45_000
                conn.requestMethod = "GET"
                conn.inputStream.bufferedReader().use { it.readText() }
            }.fold(
                onSuccess = { body -> "OK: $body" },
                onFailure = { t -> "Fail: ${t.javaClass.simpleName}: ${t.message}" },
            )

        fun parseBootstrapProgress(line: String): Int? {
            val m = Regex("""PROGRESS=(\d+)""").find(line) ?: return null
            return m.groupValues[1].toIntOrNull()?.coerceIn(0, 100)
        }
    }
}
