package org.kotlintor.circuit

/**
 * Relay-side circuit build helpers (C Tor `circuitbuild_relay.c`).
 *
 * Inventory: `L1:feature/relay/circuitbuild_relay.c`
 */
object CircuitBuildRelay {
    const val CREATE_FAST: String = "CREATE_FAST"
    const val CREATED_FAST: String = "CREATED_FAST"
    const val EXTEND2: String = "EXTEND2"
    const val EXTENDED2: String = "EXTENDED2"

    fun knownCommands(): Set<String> = setOf(CREATE_FAST, CREATED_FAST, EXTEND2, EXTENDED2)
}
