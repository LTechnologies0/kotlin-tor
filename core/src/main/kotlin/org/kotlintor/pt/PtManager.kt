package org.kotlintor.pt

import org.kotlintor.config.TorConfig
import java.io.BufferedReader
import java.io.InputStreamReader
import java.nio.file.Files
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/**
 * Managed pluggable-transport launcher (pt-spec).
 *
 * Does not reimplement obfs4/snowflake; spawns an external binary configured via
 * `TOR_PT_EXEC` / `TOR_PT_CLIENT_TRANSPORTS`, or inferred from Bridge lines
 * (`Bridge obfs4 …`, `Bridge snowflake …`).
 */
class PtManager(private val config: TorConfig) {
    private var process: Process? = null
    /** First CMETHOD socks (back-compat). */
    var socksAddress: String? = null
        private set
    /** Per-transport CMETHOD endpoints. */
    val cmethods: MutableMap<String, PtCmethod> = ConcurrentHashMap()
    var lastError: String? = null
        private set

    fun start() {
        if (!config.useBridges || config.bridges.isEmpty()) return
        val transports = configuredTransports()
        if (transports.isEmpty()) {
            lastError = "UseBridges set but no transport names in Bridge lines / TOR_PT_CLIENT_TRANSPORTS"
            return
        }
        val exec = resolveExec() ?: run {
            lastError = "no PT binary (set TOR_PT_EXEC or ClientTransportPlugin … exec PATH)"
            return
        }
        if (!Files.exists(java.nio.file.Path.of(exec))) {
            lastError = "PT exec not found: $exec"
            return
        }

        val stateDir = config.dataDirectory.resolve("pt_state")
        Files.createDirectories(stateDir)

        val pb = ProcessBuilder(exec)
        pb.environment()["TOR_PT_MANAGED_TRANSPORT_VER"] = "1"
        pb.environment()["TOR_PT_STATE_LOCATION"] = stateDir.toString()
        pb.environment()["TOR_PT_CLIENT_TRANSPORTS"] = transports.joinToString(",")
        // Meek domain-front defaults for meek_lite when operator omits env.
        if (transports.any { it.equals(MeekConfig.TRANSPORT, ignoreCase = true) }) {
            pb.environment().putIfAbsent("TOR_PT_MEEK_URL", BridgeDbClient.DEFAULT_MEEK_URL)
            pb.environment().putIfAbsent("TOR_PT_MEEK_FRONT", MeekConfig.DEFAULT_FRONT)
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
                        line.startsWith("CMETHOD ") -> {
                            val parts = line.split(' ')
                            if (parts.size >= 4) {
                                val cm = PtCmethod(parts[1], parts[2], parts[3])
                                cmethods[cm.transport] = cm
                                if (socksAddress == null) socksAddress = cm.socksAddress
                            }
                        }
                        line.startsWith("VERSION ") -> Unit
                        line.startsWith("ENV-ERROR ") || line.startsWith("VERSION-ERROR ") ->
                            lastError = line
                        line.startsWith("CMETHOD-ERROR ") -> lastError = line
                        line.startsWith("CMETHODS DONE") -> break
                    }
                }
            } catch (e: Exception) {
                lastError = e.message
            }
        }.apply { isDaemon = true; start() }
        // Brief wait for CMETHOD
        repeat(50) {
            if (socksAddress != null || lastError != null) return
            Thread.sleep(100)
        }
    }

    /** Soft-validate Bridge lines against known transport arg allowlists. */
    fun validateConfiguredBridges(): List<String> {
        val warnings = mutableListOf<String>()
        for (line in config.bridges) {
            val transportName = bridgeTransport(line) ?: continue
            val t = PtTransport.parse(transportName)
            if (t == null) {
                warnings += "unknown transport '$transportName' (still launching PT)"
                continue
            }
            val args = PtBridgeArgs.parseArgs(line)
            warnings += PtBridgeArgs.requiredPresent(t, args)
            warnings += PtBridgeArgs.validate(t, args)
        }
        return warnings
    }

    /** Resolve exec from TOR_PT_EXEC or `ClientTransportPlugin transport exec /path`. */
    fun resolveExec(): String? {
        System.getenv("TOR_PT_EXEC")?.let { return it }
        val ctp = config.clientTransportPlugin ?: return null
        // Forms: "obfs4 exec /usr/bin/obfs4proxy" or "exec /usr/bin/obfs4proxy"
        val parts = ctp.trim().split(Regex("\\s+"))
        val execIdx = parts.indexOfFirst { it.equals("exec", ignoreCase = true) }
        if (execIdx >= 0 && execIdx + 1 < parts.size) return parts[execIdx + 1]
        return parts.lastOrNull()
    }

    /** Dial [bridge] via PT SOCKS when transport is set; else direct TCP. */
    fun dialBridge(bridge: BridgeLine): java.net.Socket {
        val transport = bridge.transport
        if (transport == null) {
            return org.kotlintor.net.OutboundBind.connect(
                bridge.host,
                bridge.port,
                config.outboundBindForPt(),
                timeoutMs = 20_000,
                protect = true,
            )
        }
        val socks = cmethods[transport]?.socksAddress
            ?: socksAddress
            ?: error("PT socks not ready for $transport: ${lastError ?: "waiting"}")
        val (sh, sp) = PtSocksDialer.parseSocksAddress(socks)
        return PtSocksDialer.connect(sh, sp, bridge.host, bridge.port, protect = true)
    }

    fun firstBridge(): BridgeLine? =
        config.bridges.firstNotNullOfOrNull { BridgeLine.parse(it) }

    /** Transport names from env or Bridge lines (`obfs4`, `snowflake`, `meek_lite`, …). */
    fun configuredTransports(): List<String> {
        val fromEnv = System.getenv("TOR_PT_CLIENT_TRANSPORTS")
            ?.split(',')
            ?.map { it.trim() }
            ?.filter { it.isNotEmpty() }
            .orEmpty()
        if (fromEnv.isNotEmpty()) return fromEnv.distinct()
        return config.bridges.mapNotNull { bridgeTransport(it) }.distinct()
    }

    fun bridgeTransport(bridgeLine: String): String? {
        val parts = bridgeLine.trim().split(Regex("\\s+"))
        if (parts.isEmpty()) return null
        // Forms: "obfs4 1.2.3.4:443 …" or "1.2.3.4:443" (vanilla — no PT)
        val first = parts[0]
        if (first.contains(':') && first.firstOrNull()?.isDigit() == true) return null
        if (first.equals("bridge", ignoreCase = true)) return null
        return first
    }

    fun stop() {
        process?.destroy()
        process?.waitFor(2, TimeUnit.SECONDS)
        process = null
        cmethods.clear()
        socksAddress = null
    }
}
