package org.kotlintor.relay

import org.kotlintor.config.ListenSpec
import org.kotlintor.config.TorConfig

/**
 * C Tor naming primary.
 *
 * Inventory: `L1:feature/relay/transport_config.c`
 */
data class TransportListenAddr(
    val transport: String,
    val host: String,
    val port: Int,
)

data class TransportConfig(
    val extOrPort: ListenSpec? = null,
    val serverTransportListenAddr: List<String> = emptyList(),
    val serverTransportOptions: List<String> = emptyList(),
) {
    fun parsedListenAddrs(): List<TransportListenAddr> =
        serverTransportListenAddr.mapNotNull { parseListenLine(it) }

    companion object {
        fun fromTorConfig(c: TorConfig): TransportConfig =
            TransportConfig(
                extOrPort = c.extOrPort,
                serverTransportListenAddr = c.serverTransportListenAddr,
                serverTransportOptions = c.process.serverTransportOptions,
            )

        /** Parse `obfs4 0.0.0.0:443` style ServerTransportListenAddr. */
        fun parseListenLine(line: String): TransportListenAddr? {
            val parts = line.trim().split(Regex("\\s+"))
            if (parts.size < 2) return null
            val transport = parts[0]
            val hp = parts[1]
            val colon = hp.lastIndexOf(':')
            if (colon <= 0) return null
            val host = hp.substring(0, colon).trimStart('[', ' ').trimEnd(']')
            val port = hp.substring(colon + 1).toIntOrNull() ?: return null
            return TransportListenAddr(transport, host, port)
        }
    }
}
