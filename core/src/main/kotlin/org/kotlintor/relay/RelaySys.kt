package org.kotlintor.relay

import org.kotlintor.config.TorConfig
import java.util.concurrent.atomic.AtomicBoolean

/**
 * C Tor naming primary.
 *
 * Inventory: `L1:feature/relay/relay_sys.c`
 */
object RelaySys {
    private val started = AtomicBoolean(false)

    fun shouldRunRelay(config: TorConfig): Boolean = RouterMode.serverMode(config)

    fun shouldPublishDescriptor(config: TorConfig): Boolean =
        RouterMode.advertisedServerMode(config) && config.publishServerDescriptor

    fun init(config: TorConfig) {
        started.set(shouldRunRelay(config))
        if (started.get()) RelayMetrics.reset()
    }

    fun shutdown() {
        started.set(false)
    }

    fun isStarted(): Boolean = started.get()
}
