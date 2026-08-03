package org.kotlintor.pt

import org.kotlintor.config.TorConfig
import java.io.BufferedReader
import java.io.InputStreamReader
import java.nio.file.Files
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/**
 * Server-side PT launcher (pt-spec SMETHOD / TOR_PT_SERVER_TRANSPORTS).
 * Same external-binary model as C Tor.
 */
class PtServerManager(private val config: TorConfig) {
    private var process: Process? = null
    val smethods: MutableMap<String, String> = ConcurrentHashMap()
    var lastError: String? = null
        private set

    fun start() {
        val plugin = config.serverTransportPlugin ?: return
        val exec = resolveExec(plugin) ?: run {
            lastError = "ServerTransportPlugin missing exec path"
            return
        }
        if (!Files.exists(java.nio.file.Path.of(exec))) {
            lastError = "server PT exec not found: $exec"
            return
        }
        val transports = configuredTransports()
        if (transports.isEmpty()) {
            lastError = "no server transports configured"
            return
        }
        val stateDir = config.dataDirectory.resolve("pt_server_state")
        Files.createDirectories(stateDir)
        val orPort = config.orPort ?: config.extOrPort
        val orAddr = orPort?.let { "${it.host.ifEmpty { "127.0.0.1" }}:${it.port}" } ?: "127.0.0.1:0"

        val pb = ProcessBuilder(exec)
        pb.environment()["TOR_PT_MANAGED_TRANSPORT_VER"] = "1"
        pb.environment()["TOR_PT_STATE_LOCATION"] = stateDir.toString()
        pb.environment()["TOR_PT_SERVER_TRANSPORTS"] = transports.joinToString(",")
        pb.environment()["TOR_PT_ORPORT"] = orAddr
        if (config.extOrPort != null) {
            val e = config.extOrPort
            pb.environment()["TOR_PT_EXTENDED_SERVER_PORT"] =
                "${e.host.ifEmpty { "127.0.0.1" }}:${e.port}"
        }
        val bind = config.serverTransportListenAddr.joinToString(",")
        if (bind.isNotEmpty()) {
            pb.environment()["TOR_PT_SERVER_BINDADDR"] = bind
        }
        pb.redirectErrorStream(true)
        val proc = pb.start()
        process = proc
        val reader = BufferedReader(InputStreamReader(proc.inputStream))
        Thread {
            try {
                while (true) {
                    val line = reader.readLine() ?: break
                    when {
                        line.startsWith("SMETHOD ") -> {
                            val parts = line.split(' ', limit = 3)
                            if (parts.size >= 3) smethods[parts[1]] = parts[2]
                        }
                        line.startsWith("ENV-ERROR ") || line.startsWith("VERSION-ERROR ") ||
                            line.startsWith("SMETHOD-ERROR ") -> lastError = line
                        line.startsWith("SMETHODS DONE") -> break
                    }
                }
            } catch (e: Exception) {
                lastError = e.message
            }
        }.apply { isDaemon = true; start() }
        repeat(50) {
            if (smethods.isNotEmpty() || lastError != null) return
            Thread.sleep(100)
        }
    }

    fun configuredTransports(): List<String> {
        val fromListen = config.serverTransportListenAddr.mapNotNull {
            it.trim().substringBefore(' ').takeIf { t -> t.isNotEmpty() }
        }
        if (fromListen.isNotEmpty()) return fromListen.distinct()
        val plugin = config.serverTransportPlugin ?: return emptyList()
        val parts = plugin.trim().split(Regex("\\s+"))
        val execIdx = parts.indexOfFirst { it.equals("exec", ignoreCase = true) }
        val names = if (execIdx > 0) parts.subList(0, execIdx) else parts.take(1)
        return names.filter { !it.equals("exec", true) && it.isNotEmpty() }
    }

    private fun resolveExec(plugin: String): String? {
        val parts = plugin.trim().split(Regex("\\s+"))
        val execIdx = parts.indexOfFirst { it.equals("exec", ignoreCase = true) }
        if (execIdx >= 0 && execIdx + 1 < parts.size) return parts[execIdx + 1]
        return parts.lastOrNull()
    }

    fun stop() {
        process?.destroy()
        process?.waitFor(2, TimeUnit.SECONDS)
        process = null
        smethods.clear()
    }
}
