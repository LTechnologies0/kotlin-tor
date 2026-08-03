package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.circuit.Circpad
import org.kotlintor.circuit.CircpadHistogram
import org.kotlintor.circuit.CircpadMachineConditions
import org.kotlintor.circuit.CircpadTokenRemoval
import org.kotlintor.circuit.CircuitMux
import org.kotlintor.circuit.CircuitPaddingMachines
import org.kotlintor.circuit.EwmaCircuitMuxPolicy

class CircpadCmuxFairElevationTest {
    @Test
    fun `machine conditions gate intro hide apply`() {
        val selected = CircuitPaddingMachines.selectApplicable(
            hopCount = 3,
            circFlags = Circpad.CircState.OPENED or Circpad.CircState.NO_STREAMS,
            originSide = true,
        )
        assertNotNull(selected)
        assertEquals("client_ip_circ", selected!!.name)

        assertNull(
            CircuitPaddingMachines.selectApplicable(
                hopCount = 1,
                circFlags = Circpad.CircState.OPENED,
                originSide = true,
            ),
        )

        val needsV = CircpadMachineConditions(minHops = 2, requiresVanguards = true)
        assertTrue(
            !needsV.mayApply(
                hopCount = 3,
                circFlags = Circpad.CircState.OPENED,
                purposeMask = CircpadMachineConditions.PURPOSE_ALL,
                vanguardsEnabled = false,
                reducedPadding = false,
            ),
        )
    }

    @Test
    fun `token removal HIGHER skips empty exact bin`() {
        val h = CircpadHistogram(
            tokens = intArrayOf(0, 3, 2),
            edgesUs = longArrayOf(0, 100, 200),
            removal = CircpadTokenRemoval.HIGHER,
        )
        val before = h.remainingTokens()
        h.removeTokenForDelay(50) // exact bin 0 empty → higher
        assertEquals(before - 1, h.remainingTokens())
    }

    @Test
    fun `cmux flushFair spreads cells across circuits`() {
        val mux = CircuitMux(EwmaCircuitMuxPolicy(halfLifeSec = 30.0))
        mux.attach(1)
        mux.attach(2)
        mux.attach(3)
        repeat(4) { mux.enqueue(1, byteArrayOf(1)) }
        repeat(4) { mux.enqueue(2, byteArrayOf(2)) }
        repeat(4) { mux.enqueue(3, byteArrayOf(3)) }
        val flushed = mux.flushFair(maxItems = 9)
        assertEquals(9, flushed.size)
        val byCirc = flushed.filterIsInstance<CircuitMux.FlushItem.Cell>()
            .groupingBy { it.circId }
            .eachCount()
        assertEquals(3, byCirc.size)
        assertTrue(byCirc.values.all { it == 3 }, "byCirc=$byCirc")
    }
}
