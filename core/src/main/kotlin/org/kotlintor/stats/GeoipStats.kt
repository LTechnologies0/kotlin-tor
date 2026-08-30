package org.kotlintor.stats

/**
 * Naming primary for `geoip_stats.c` (STEM GeoipStats).
 *
 * Inventory: `L1:feature/stats/geoip_stats.c`
 *
 * Implementation: [GeoIpStats].
 */
object GeoipStats {
    fun entryEnabled(): Boolean = GeoIpStats.entryEnabled

    fun setEntryEnabled(v: Boolean) {
        GeoIpStats.entryEnabled = v
    }

    fun formatEntryStats(): String = GeoIpStats.formatEntryStats()
}
