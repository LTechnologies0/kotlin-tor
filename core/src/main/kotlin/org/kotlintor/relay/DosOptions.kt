package org.kotlintor.relay

/**
 * DoS subsystem options (C Tor `dos_options_t` / dos_options.inc).
 */
data class DosOptions(
    val circuitCreationEnabled: Boolean = true,
    val circuitCreationMinConnections: Int = 3,
    val circuitCreationRate: Int = 100,
    val circuitCreationBurst: Int = 8,
    val connectionEnabled: Boolean = true,
    val connectionMaxConcurrent: Int = 32,
    val streamCreationEnabled: Boolean = false,
    val streamCreationRate: Int = 100,
    val streamCreationBurst: Int = 50,
    val refuseSingleHopClientRendezvous: Boolean = true,
) {
    fun toGuard(): DosGuard = DosGuard(
        maxConnsPerIp = if (connectionEnabled) connectionMaxConcurrent else Int.MAX_VALUE / 4,
        maxCreatesPerMin = if (circuitCreationEnabled) circuitCreationRate else Int.MAX_VALUE / 4,
        maxConcurrentCreates = if (circuitCreationEnabled) circuitCreationBurst else Int.MAX_VALUE / 4,
        maxStreamsPerMin = if (streamCreationEnabled) streamCreationRate else Int.MAX_VALUE / 4,
        streamDefenseEnabled = streamCreationEnabled,
    )
}
