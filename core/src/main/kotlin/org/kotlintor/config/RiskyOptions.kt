package org.kotlintor.config

/**
 * Risky / testing options gate (C Tor `risky_options.c`).
 *
 * Inventory: `L1:app/main/risky_options.c`
 */
object RiskyOptions {
    fun testingTorNetwork(c: TorConfig): Boolean = c.testingTorNetwork

    fun allowNonStandard(c: TorConfig): Boolean = c.testingTorNetwork || !c.clientOnly
}
