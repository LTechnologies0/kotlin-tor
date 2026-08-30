package org.kotlintor.relay

import java.util.concurrent.atomic.AtomicLong

/**
 * C Tor naming primary.
 *
 * Inventory: `L1:feature/relay/relay_metrics.c`
 */
object RelayMetrics {
    private val cellsRelayed = AtomicLong(0)
    private val circuitsCreated = AtomicLong(0)
    private val exitStreams = AtomicLong(0)
    private val orConns = AtomicLong(0)
    private val descriptorsPublished = AtomicLong(0)

    fun noteCell() { cellsRelayed.incrementAndGet() }
    fun noteCircuit() { circuitsCreated.incrementAndGet() }
    fun noteExitStream() { exitStreams.incrementAndGet() }
    fun noteOrConn() { orConns.incrementAndGet() }
    fun noteDescriptorPublished() { descriptorsPublished.incrementAndGet() }

    fun snapshot(): Map<String, Long> = mapOf(
        "relay_cells" to cellsRelayed.get(),
        "relay_circuits" to circuitsCreated.get(),
        "relay_exit_streams" to exitStreams.get(),
        "relay_or_conns" to orConns.get(),
        "relay_descriptors_published" to descriptorsPublished.get(),
    )

    fun exportPrometheus(): String = buildString {
        for ((k, v) in snapshot()) append("tor_").append(k).append(' ').append(v).append('\n')
    }

    fun reset() {
        cellsRelayed.set(0)
        circuitsCreated.set(0)
        exitStreams.set(0)
        orConns.set(0)
        descriptorsPublished.set(0)
    }
}
