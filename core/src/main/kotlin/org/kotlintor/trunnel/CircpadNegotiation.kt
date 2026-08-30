package org.kotlintor.trunnel

import org.kotlintor.circuit.CircpadNegotiate

/**
 * Circuit padding negotiation trunnel (C Tor `circpad_negotiation.c`).
 *
 * Inventory: `L1:trunnel/circpad_negotiation.c`
 */
object CircpadNegotiation {
    fun encodeStart(
        machineType: Int = CircpadNegotiate.MACHINE_CIRC_SETUP,
        machineCtr: Long = 0,
    ): ByteArray =
        CircpadNegotiate.encodeNegotiate(
            CircpadNegotiate.Negotiate(
                command = CircpadNegotiate.COMMAND_START,
                machineType = machineType,
                machineCtr = machineCtr,
            ),
        )

    fun parseNegotiated(body: ByteArray): CircpadNegotiate.Negotiated =
        CircpadNegotiate.parseNegotiated(body)
}
