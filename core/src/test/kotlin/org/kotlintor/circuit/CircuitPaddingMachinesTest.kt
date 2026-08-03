package org.kotlintor.circuit

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.cell.RelayCommand

class CircuitPaddingMachinesTest {
    @Test
    fun `builtin machines match C Tor names and intro bounds`() {
        val intro = CircuitPaddingMachines.clientHideIntro()
        assertEquals("client_ip_circ", intro.name)
        assertEquals(2, intro.targetHopNum)
        assertTrue(intro.originSide)
        assertEquals(7, CircuitPaddingMachines.INTRO_MACHINE_MINIMUM_PADDING)
        assertEquals(10, CircuitPaddingMachines.INTRO_MACHINE_MAXIMUM_PADDING)
        repeat(20) {
            val n = CircuitPaddingMachines.samplePaddingCount(intro)
            assertTrue(n in 7..10)
        }
    }

    @Test
    fun `dropCells produce RELAY DROP`() {
        val cells = CircuitPaddingMachines.dropCells(3)
        assertEquals(3, cells.size)
        assertTrue(cells.all { it.command == RelayCommand.DROP && it.streamId == 0 })
    }

    @Test
    fun `intro session negotiate then arm drops`() = kotlinx.coroutines.runBlocking {
        val sent = mutableListOf<RelayCommand>()
        val session = CircuitPaddingSession(
            CircuitPaddingMachines.clientHideIntro(),
            sendDrop = { sent += it.command },
            sendNegotiate = { sent += it.command },
        )
        session.negotiateStart(machineCtr = 3)
        assertTrue(sent.contains(RelayCommand.PADDING_NEGOTIATE))
        // Simulate middle OK reply.
        val ok = CircpadNegotiate.replyOk(
            CircpadNegotiate.Negotiate(
                command = CircpadNegotiate.COMMAND_START,
                machineType = CircpadNegotiate.MACHINE_CIRC_SETUP,
                machineCtr = 3,
            ),
        )
        assertTrue(session.onNegotiated(ok.data))
        assertTrue(session.negotiatedOk)
        session.onIntroduce1Sent()
        session.flushPendingDrops()
        assertTrue(session.isComplete)
        assertTrue(sent.count { it == RelayCommand.DROP } in 7..10)
    }
}
