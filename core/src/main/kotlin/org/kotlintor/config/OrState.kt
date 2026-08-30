package org.kotlintor.config

import java.nio.file.Path

/**
 * Persistent Tor state mirror (C Tor `or_state_t`).
 *
 * Inventory: `L2:app/config/or_state_t`, `L2:core/or/or_state_t`
 *
 * Runtime options live in [TorConfig]; this names the on-disk state surface.
 */
data class OrState(
    val dataDirectory: Path,
    val lastRotatedOnionKeyEpochSec: Long = 0,
    val totalBandwidthRead: Long = 0,
    val totalBandwidthWritten: Long = 0,
) {
    companion object {
        fun fromTorConfig(c: TorConfig): OrState =
            OrState(dataDirectory = c.dataDirectory)
    }
}
