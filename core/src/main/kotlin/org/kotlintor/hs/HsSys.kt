package org.kotlintor.hs

import org.kotlintor.config.TorConfig

/**
 * C Tor naming primary.
 *
 * Inventory: `L1:feature/hs/hs_sys.c`
 */
object HsSys {
    @Volatile
    private var started: Boolean = false

    fun enabled(config: TorConfig): Boolean =
        config.hiddenServices.isNotEmpty() || HsOpts.fromTorConfig(config).services.isNotEmpty()

    fun init(config: TorConfig) {
        started = enabled(config)
        if (started) HsMetrics.reset()
    }

    fun shutdown() {
        started = false
        HsDosDefense.shared.clear()
    }

    fun isStarted(): Boolean = started
}
