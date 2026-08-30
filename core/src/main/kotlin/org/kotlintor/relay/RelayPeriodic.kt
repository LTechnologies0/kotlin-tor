package org.kotlintor.relay

import org.kotlintor.config.TorConfig

/**
 * C Tor naming primary.
 *
 * Inventory: `L1:feature/relay/relay_periodic.c`
 */
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
