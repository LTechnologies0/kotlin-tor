package org.kotlintor.relay

import org.kotlintor.config.TorConfig
import java.util.concurrent.atomic.AtomicBoolean

/**
 * OR / relay subsystem (C Tor `or_sys.c`).
 *
 * Inventory: `L1:core/or/or_sys.c`
 *
 * Wraps [RelaySys] start/stop for subsystem-list parity.
 */
object OrSys {
    const val SUBSYS_NAME: String = "or"

    private val initialized = AtomicBoolean(false)

    /** C Tor `subsys_or_initialize`. */
    fun initialize(config: TorConfig): Int {
        if (!initialized.compareAndSet(false, true)) return 0
        RelaySys.init(config)
        return 0
    }

    fun shutdown() {
        if (!initialized.compareAndSet(true, false)) return
        RelaySys.shutdown()
    }

    fun isInitialized(): Boolean = initialized.get()

    fun shouldRunRelay(config: TorConfig): Boolean = RelaySys.shouldRunRelay(config)

    @Volatile private var ocircPubsub = false
    @Volatile private var orconnPubsub = false

    /** C Tor `ocirc_add_pubsub`. */
    fun ocircAddPubsub(): Int {
        ocircPubsub = true
        return 0
    }

    /** C Tor `orconn_add_pubsub`. */
    fun orconnAddPubsub(): Int {
        orconnPubsub = true
        return 0
    }

    fun hasOcircPubsub(): Boolean = ocircPubsub
    fun hasOrconnPubsub(): Boolean = orconnPubsub
}
