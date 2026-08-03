package org.kotlintor.relay

import org.kotlintor.config.ListenSpec
import org.kotlintor.config.TorConfig
import org.kotlintor.net.PrivateAddresses
import java.net.InetAddress
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Relay config / address discovery / subsystem hooks
 * (C Tor `relay_config`, `relay_find_addr`, `relay_sys`, `relay_periodic`,
 * `relay_metrics`, `relay_handshake`, `transport_config`).
 *
 * Inventory:
 * - `L1:feature/relay/relay_config.c`
 * - `L1:feature/relay/relay_find_addr.c`
 * - `L1:feature/relay/relay_sys.c`
 * - `L1:feature/relay/relay_periodic.c`
 * - `L1:feature/relay/relay_metrics.c`
 * - `L1:feature/relay/relay_handshake.c`
 * - `L1:feature/relay/transport_config.c`
 */
data class RelayConfigView(
    val orPort: ListenSpec?,
    val dirPort: ListenSpec?,
    val nickname: String?,
    val contact: String?,
    val address: String?,
    val bridgeRelay: Boolean,
    val exitRelay: Boolean,
    val publishServerDescriptor: Boolean,
) {
    fun validate(): List<String> {
        val errs = mutableListOf<String>()
        if (orPort == null) errs += "ORPort required for relay"
        if (nickname != null && (nickname.length > 19 || !nickname.all { it.isLetterOrDigit() || it == '-' })) {
            errs += "Nickname invalid"
        }
        if (bridgeRelay && exitRelay) errs += "BridgeRelay and ExitRelay conflict"
        return errs
    }

    companion object {
        fun fromTorConfig(c: TorConfig): RelayConfigView =
            RelayConfigView(
                orPort = c.orPort,
                dirPort = c.dirPort,
                nickname = c.nickname,
                contact = c.contactInfo,
                address = c.address,
                bridgeRelay = c.bridgeRelay,
                exitRelay = c.exitRelay,
                publishServerDescriptor = c.publishServerDescriptor,
            )
    }
}

object RelayFindAddr {
    /**
     * Prefer configured Address=, else first non-private NIC IPv4, else null.
     * C Tor `relay_find_addr_to_publish`.
     */
    fun addressToPublish(config: TorConfig): String? {
        config.address?.trim()?.takeIf { it.isNotEmpty() }?.let { return it }
        return runCatching {
            InetAddress.getAllByName(InetAddress.getLocalHost().hostName)
                .mapNotNull { it.hostAddress }
                .firstOrNull { !PrivateAddresses.isPrivate(it) && !it.contains(':') }
        }.getOrNull()
            ?: runCatching {
                NetworkInterfaceAddrs.firstPublicIpv4()
            }.getOrNull()
    }

    /** Prefer first public IPv6 for dual-stack advertisement (when present). */
    fun ipv6ToPublish(config: TorConfig): String? {
        val configured = config.address?.trim()?.takeIf { it.contains(':') }
        if (configured != null) return configured
        return NetworkInterfaceAddrs.firstPublicIpv6()
    }

    fun suggestAddresses(config: TorConfig): Pair<String?, String?> =
        addressToPublish(config) to ipv6ToPublish(config)
}

internal object NetworkInterfaceAddrs {
    fun firstPublicIpv4(): String? {
        val ifaces = java.net.NetworkInterface.getNetworkInterfaces() ?: return null
        for (ni in ifaces) {
            if (!ni.isUp || ni.isLoopback) continue
            for (addr in ni.inetAddresses) {
                val h = addr.hostAddress ?: continue
                if (h.contains(':') || h.contains('%')) continue
                if (!PrivateAddresses.isPrivate(h)) return h
            }
        }
        return null
    }

    fun firstPublicIpv6(): String? {
        val ifaces = java.net.NetworkInterface.getNetworkInterfaces() ?: return null
        for (ni in ifaces) {
            if (!ni.isUp || ni.isLoopback) continue
            for (addr in ni.inetAddresses) {
                var h = addr.hostAddress ?: continue
                if (!h.contains(':')) continue
                if (h.contains('%')) h = h.substringBefore('%')
                if (h.startsWith("fe80", ignoreCase = true)) continue
                if (PrivateAddresses.isPrivate(h)) continue
                return h
            }
        }
        return null
    }
}

object RelaySys {
    private val started = AtomicBoolean(false)

    fun shouldRunRelay(config: TorConfig): Boolean = RouterMode.serverMode(config)

    fun shouldPublishDescriptor(config: TorConfig): Boolean =
        RouterMode.advertisedServerMode(config) && config.publishServerDescriptor

    fun init(config: TorConfig) {
        started.set(shouldRunRelay(config))
        if (started.get()) RelayMetrics.reset()
    }

    fun shutdown() {
        started.set(false)
    }

    fun isStarted(): Boolean = started.get()
}

object RelayPeriodic {
    /** Suggested seconds between descriptor rebuild attempts. */
    fun descriptorRepublishIntervalSec(config: TorConfig): Long =
        if (config.bridgeRelay) 3600 else 18 * 3600

    /** Reachability / ORPort check interval (C Tor CHECK_DESCRIPTOR). */
    fun checkDescriptorIntervalSec(): Long = 60

    /** Heartbeat / metrics flush interval. */
    fun metricsFlushIntervalSec(): Long = 300

    fun scheduleHints(config: TorConfig): Map<String, Long> = mapOf(
        "republish_sec" to descriptorRepublishIntervalSec(config),
        "check_descriptor_sec" to checkDescriptorIntervalSec(),
        "metrics_flush_sec" to metricsFlushIntervalSec(),
    )
}

object RelayMetrics {
    private val cellsRelayed = AtomicLong(0)
    private val circuitsCreated = AtomicLong(0)
    private val exitStreams = AtomicLong(0)
    private val orConns = AtomicLong(0)
    private val descriptorsPublished = AtomicLong(0)

    fun noteCell() { cellsRelayed.incrementAndGet() }
    fun noteCircuit() { circuitsCreated.incrementAndGet() }
    fun noteExitStream() { exitStreams.incrementAndGet() }
    fun noteOrConn() { orConns.incrementAndGet() }
    fun noteDescriptorPublished() { descriptorsPublished.incrementAndGet() }

    fun snapshot(): Map<String, Long> = mapOf(
        "relay_cells" to cellsRelayed.get(),
        "relay_circuits" to circuitsCreated.get(),
        "relay_exit_streams" to exitStreams.get(),
        "relay_or_conns" to orConns.get(),
        "relay_descriptors_published" to descriptorsPublished.get(),
    )

    fun exportPrometheus(): String = buildString {
        for ((k, v) in snapshot()) append("tor_").append(k).append(' ').append(v).append('\n')
    }

    fun reset() {
        cellsRelayed.set(0)
        circuitsCreated.set(0)
        exitStreams.set(0)
        orConns.set(0)
        descriptorsPublished.set(0)
    }
}

/**
 * ExtOR / PT listen config (C Tor `transport_config.c`).
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

/**
 * OR handshake capability summary (C Tor `relay_handshake.c` — capability flags + state).
 * Inventory: `L1:feature/relay/relay_handshake.c`
 */
enum class RelayHandshakeState {
    NONE,
    VERSIONS,
    CERTS,
    AUTH_CHALLENGE,
    AUTHENTICATE,
    NETINFO,
    OPEN,
}

object RelayHandshake {
    private val recent = CopyOnWriteArrayList<RelayHandshakeState>()

    fun advertisedLinkVersions(config: TorConfig): List<Int> = listOf(3, 4, 5)

    fun supportsCreateFast(config: TorConfig): Boolean = true

    fun supportsNtor(config: TorConfig): Boolean = true

    fun noteState(state: RelayHandshakeState) {
        recent += state
        while (recent.size > 64) recent.removeAt(0)
    }

    fun lastStates(): List<RelayHandshakeState> = recent.toList()

    fun clear() = recent.clear()
}
