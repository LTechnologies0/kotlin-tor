package org.kotlintor.hs

/**
 * HS metrics entry catalog (C Tor `hs_metrics_entry.c`).
 *
 * Inventory: `L1:feature/hs/hs_metrics_entry.c`
 */
object HsMetricsEntry {
    val KEYS: Set<String> = setOf(
        "hs_intro_received",
        "hs_intro_rejected",
        "hs_desc_fetches",
        "hs_desc_uploads",
        "hs_rendezvous_ok",
    )

    fun values(): Map<String, Int> = HsMetrics.snapshot()
}
