package org.kotlintor.relay

import org.kotlintor.config.TorConfig
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * DoS subsystem init/shutdown (C Tor `dos_sys.c`).
 *
 * Inventory: `L1:core/or/dos_sys.c`
 */
object DosSys {
    const val SUBSYS_NAME: String = "dos"
    const val SUBSYS_LEVEL: Int = 21 // DOS_SUBSYS_LEVEL

    private val initialized = AtomicBoolean(false)
    private val guard = AtomicReference<DosGuard?>(null)

    /** C Tor `subsys_dos_initialize`. */
    fun initialize(config: TorConfig? = null): Int {
        if (!initialized.compareAndSet(false, true)) return 0
        guard.set(
            DosGuard(
                maxConnsPerIp = config?.runtime?.let { 32 } ?: 32,
            ),
        )
        return 0
    }

    /** C Tor `subsys_dos_shutdown`. */
    fun shutdown() {
        if (!initialized.compareAndSet(true, false)) return
        guard.set(null)
    }

    fun isInitialized(): Boolean = initialized.get()

    fun guard(): DosGuard? = guard.get()

    fun allowConnection(ip: String): Boolean =
        guard.get()?.allowConnection(ip) ?: true

    fun allowCreate(ip: String): Boolean =
        guard.get()?.allowCreate(ip) ?: true

    private val options = AtomicReference(DosOptions())

    /** C Tor `dos_get_options`. */
    fun dosGetOptions(): DosOptions = options.get()

    fun setOptionsForTests(o: DosOptions) = options.set(o)
}
