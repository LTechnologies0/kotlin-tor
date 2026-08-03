package org.kotlintor.circuit

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CircpadStateMachineTest {
    @Test
    fun `wtf pad lite START to BURST to GAP to END`() {
        val m = CircpadStateMachine(CircpadStateMachine.wtfPadLite())
        assertEquals(CircpadStates.START, m.stateIndex)
        assertEquals(Circpad.Decision.CHANGED, m.onEvent(Circpad.Event.NONPADDING_SENT))
        assertEquals(CircpadStates.BURST, m.stateIndex)
        assertEquals(Circpad.Decision.CHANGED, m.onPaddingSent())
        assertEquals(CircpadStates.GAP, m.stateIndex)
        assertFalse(m.ended)
        assertEquals(Circpad.Decision.CHANGED, m.onEvent(Circpad.Event.BINS_EMPTY))
        assertTrue(m.ended)
    }

    @Test
    fun `CANCEL ends scheduling`() {
        val next = IntArray(CircpadStates.NUM_EVENTS) { CircpadStates.IGNORE }
        next[Circpad.Event.NONPADDING_SENT.ordinal] = CircpadStates.CANCEL
        val spec = CircpadMachineSpec(
            name = "cancel_test",
            states = listOf(CircpadStateDef("s0", next)),
        )
        val m = CircpadStateMachine(spec)
        assertEquals(Circpad.Decision.CHANGED, m.onEvent(Circpad.Event.NONPADDING_SENT))
        assertTrue(m.cancelled)
        assertEquals(Circpad.DELAY_INFINITE, m.nextDelayUs)
    }
}
