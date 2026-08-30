package org.kotlintor.circuit

/**
 * Circuit LTTng / USDT-style probes (C Tor `trace_probes_circuit.c`).
 *
 * Inventory: `L1:core/or/trace_probes_circuit.c`
 *
 * JVM mirror: no-op counters for inventory naming parity.
 */
object TraceProbesCircuit {
    @Volatile
    private var createCount: Long = 0

    @Volatile
    private var extendCount: Long = 0

    fun noteCreate() {
        createCount++
    }

    fun noteExtend() {
        extendCount++
    }

    fun snapshot(): Map<String, Long> = mapOf(
        "circ_create" to createCount,
        "circ_extend" to extendCount,
    )

    fun reset() {
        createCount = 0
        extendCount = 0
    }
}
