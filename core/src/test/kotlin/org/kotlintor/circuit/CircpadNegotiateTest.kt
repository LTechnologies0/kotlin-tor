package org.kotlintor.circuit

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.cell.RelayCommand

class CircpadNegotiateTest {
    @Test
    fun `negotiate start stop roundtrip`() {
        val cell = CircpadNegotiate.startCell(machineCtr = 7)
        assertEquals(RelayCommand.PADDING_NEGOTIATE, cell.command)
        val n = CircpadNegotiate.parseNegotiate(cell.data)
        assertEquals(CircpadNegotiate.COMMAND_START, n.command)
        assertEquals(7L, n.machineCtr)
        assertEquals(CircpadNegotiate.MACHINE_CIRC_SETUP, n.machineType)

        val session = CircpadNegotiateSession()
        val reply = session.handleNegotiate(cell.data)
        assertEquals(RelayCommand.PADDING_NEGOTIATED, reply.command)
        assertNotNull(session.machine)
        val negotiated = CircpadNegotiate.parseNegotiated(reply.data)
        assertEquals(CircpadNegotiate.RESPONSE_OK, negotiated.response)

        val stop = CircpadNegotiate.stopCell(machineCtr = 7)
        session.handleNegotiate(stop.data)
        assertNull(session.machine)
    }

    @Test
    fun `unknown machine type returns ERR`() {
        val session = CircpadNegotiateSession()
        val bad = CircpadNegotiate.encodeNegotiate(
            CircpadNegotiate.Negotiate(
                command = CircpadNegotiate.COMMAND_START,
                machineType = 99,
                machineCtr = 1,
            ),
        )
        val reply = session.handleNegotiate(bad)
        assertEquals(CircpadNegotiate.RESPONSE_ERR, CircpadNegotiate.parseNegotiated(reply.data).response)
        assertTrue(session.machine == null)
    }
}
