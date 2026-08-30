package org.kotlintor.metrics

import org.kotlintor.config.TorConfig
import org.kotlintor.hs.HsMetrics
import org.kotlintor.relay.RelayMetrics
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Metrics subsystem setup/teardown (C Tor `metrics_sys.c` / `sys_metrics`).
 *
 * Inventory: `L1:feature/metrics/metrics_sys.c`
 *
 * C Tor: `subsys_metrics_initialize` → `metrics_init`;
 * `subsys_metrics_shutdown` → `metrics_cleanup`.
 */
object MetricsSys {
    const val SUBSYS_NAME: String = "metrics"
    const val SUBSYS_LEVEL: Int = 50 // METRICS_SUBSYS_LEVEL order-of-magnitude; C uses numeric level

    private val initialized = AtomicBoolean(false)

    fun enabled(config: TorConfig): Boolean = config.metricsPort != null

    fun shouldBind(config: TorConfig): Boolean = enabled(config) && initialized.get()

    /** C Tor `subsys_metrics_initialize` / `metrics_init`. */
    fun initialize(): Int {
        if (!initialized.compareAndSet(false, true)) return 0
        RelayMetrics.reset()
        HsMetrics.reset()
        return 0
    }

    /** C Tor `subsys_metrics_shutdown` / `metrics_cleanup`. */
    fun shutdown() {
        if (!initialized.compareAndSet(true, false)) return
        RelayMetrics.reset()
        HsMetrics.reset()
    }

    fun isInitialized(): Boolean = initialized.get()

    fun snapshot(): Map<String, Long> {
        val out = LinkedHashMap<String, Long>()
        RelayMetrics.snapshot().forEach { (k, v) -> out[k] = v }
        HsMetrics.snapshot().forEach { (k, v) -> out[k] = v.toLong() }
        return out
    }

    /** Prometheus text export when the metrics port is bound. */
    fun exportPrometheus(): String {
        if (!initialized.get()) return ""
        val sb = StringBuilder()
        for ((k, v) in snapshot()) {
            sb.append("# TYPE tor_").append(k.replace('.', '_')).append(" counter\n")
            sb.append("tor_").append(k.replace('.', '_')).append(' ').append(v).append('\n')
        }
        return sb.toString()
    }
}
