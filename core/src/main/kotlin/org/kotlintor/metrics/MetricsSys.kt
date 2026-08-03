package org.kotlintor.metrics

import org.kotlintor.config.TorConfig
import org.kotlintor.relay.RelayMetrics
import org.kotlintor.hs.HsMetrics

/**
 * Metrics subsystem hooks (C Tor `metrics_sys.c` lite).
 *
 * Inventory: `L1:feature/metrics/metrics_sys.c`
 */
object MetricsSys {
    fun enabled(config: TorConfig): Boolean = config.metricsPort != null

    fun snapshot(): Map<String, Long> {
        val out = LinkedHashMap<String, Long>()
        RelayMetrics.snapshot().forEach { (k, v) -> out[k] = v }
        HsMetrics.snapshot().forEach { (k, v) -> out[k] = v.toLong() }
        return out
    }

    fun shouldBind(config: TorConfig): Boolean = enabled(config)
}
