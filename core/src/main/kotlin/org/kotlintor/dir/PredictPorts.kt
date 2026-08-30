package org.kotlintor.dir

import java.util.concurrent.ConcurrentHashMap

/**
 * Port prediction for circuit prebuild (C Tor `predict_ports.c`).
 *
 * Inventory: `L1:feature/stats/predict_ports.c`
 */
object PredictPorts {
    private val counts = ConcurrentHashMap<Int, Int>()

    fun noteUse(port: Int) {
        if (port in 1..65535) counts.merge(port, 1, Int::plus)
    }

    fun predicted(limit: Int = 8): List<Int> =
        counts.entries.sortedByDescending { it.value }.take(limit).map { it.key }

    fun clear() = counts.clear()
}
