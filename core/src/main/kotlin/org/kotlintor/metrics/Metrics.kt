package org.kotlintor.metrics

/**
 * Metrics export surface (C Tor `metrics.c`).
 *
 * Inventory: `L1:feature/metrics/metrics.c`
 *
 * Lifecycle: [MetricsSys].
 */
object Metrics {
    fun initialize(): Int = MetricsSys.initialize()

    fun shutdown() = MetricsSys.shutdown()

    fun isInitialized(): Boolean = MetricsSys.isInitialized()

    fun exportPrometheus(): String = MetricsSys.exportPrometheus()
}
