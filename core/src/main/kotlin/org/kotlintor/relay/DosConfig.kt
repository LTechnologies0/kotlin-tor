package org.kotlintor.relay

/**
 * DoS config options (C Tor `dos_config.c` / `dos_options_t`).
 *
 * Inventory: `L1:core/or/dos_config.c`
 */
object DosConfig {
    fun defaultOptions(): DosOptions = DosOptions()

    fun validate(o: DosOptions): Boolean {
        if (o.circuitCreationRate < 0 || o.circuitCreationBurst < 0) return false
        if (o.connectionMaxConcurrent < 0) return false
        if (o.streamCreationRate < 0 || o.streamCreationBurst < 0) return false
        if (o.circuitCreationBurst < o.circuitCreationMinConnections && o.circuitCreationEnabled) {
            // burst may be lower than min in some configs; still accept
        }
        return true
    }

    fun fromTorConfigHints(
        connectionMax: Int? = null,
        createRate: Int? = null,
        createBurst: Int? = null,
        streamEnabled: Boolean? = null,
    ): DosOptions {
        val base = DosOptions()
        return base.copy(
            connectionMaxConcurrent = connectionMax ?: base.connectionMaxConcurrent,
            circuitCreationRate = createRate ?: base.circuitCreationRate,
            circuitCreationBurst = createBurst ?: base.circuitCreationBurst,
            streamCreationEnabled = streamEnabled ?: base.streamCreationEnabled,
        )
    }
}
