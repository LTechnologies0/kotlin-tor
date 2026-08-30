package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.kotlintor.cell.CircuitPurpose
import org.kotlintor.circuit.CircuitKind
import org.kotlintor.circuit.CircuitList
import org.kotlintor.circuit.CircuitState

/**
 * Elevates `L1:core/or/circuitlist.c` D2→D3.
 *
 * Evidence: purpose matrix strings, mark-for-close, global origin list,
 * opened-circuit cache vs circuitlist.c.
 */
class CircuitListElevationTest {
    @BeforeEach
    fun clear() {
        CircuitList.clear()
    }

    @Test
    fun `purpose controller and hs state strings`() {
        assertEquals("GENERAL", CircuitList.purposeToControllerString(CircuitPurpose.GENERAL))
        assertEquals("HS_CLIENT_INTRO", CircuitList.purposeToControllerString(CircuitPurpose.HS_CLIENT_INTRODUCING))
        assertEquals("HS_CLIENT_REND", CircuitList.purposeToControllerString(CircuitPurpose.HS_CLIENT_REND_JOINED))
        assertEquals("CONFLUX_LINKED", CircuitList.purposeToControllerString(CircuitPurpose.CONFLUX_LINKED))
        assertEquals("SERVER", CircuitList.purposeToControllerString(CircuitPurpose.OR))
        assertEquals("HSCI_CONNECTING", CircuitList.purposeToHsStateString(CircuitPurpose.HS_CLIENT_INTRODUCING))
        assertEquals("HSCR_JOINED", CircuitList.purposeToHsStateString(CircuitPurpose.HS_CLIENT_REND_JOINED))
        assertNull(CircuitList.purposeToHsStateString(CircuitPurpose.GENERAL))
        assertEquals("General-purpose client", CircuitList.purposeToString(CircuitPurpose.GENERAL))
        assertEquals("Linked conflux circuit", CircuitList.purposeToString(CircuitPurpose.CONFLUX_LINKED))
        assertEquals(5, CircuitPurpose.GENERAL.code)
        assertEquals(26, CircuitPurpose.CONFLUX_LINKED.code)
    }

    @Test
    fun `state strings and mark for close`() {
        assertEquals("doing handshakes", CircuitList.stateToString(CircuitState.BUILDING))
        assertEquals("open", CircuitList.stateToString(CircuitState.OPEN))
        CircuitList.registerOrigin(1, CircuitPurpose.GENERAL)
        CircuitList.registerOrigin(2, CircuitPurpose.HS_CLIENT_HSDIR)
        CircuitList.registerOr(3, isExit = true)
        assertEquals(2, CircuitList.globalOriginList().size)
        assertEquals(3, CircuitList.globalList().size)
        assertTrue(CircuitList.markForClose(1))
        assertEquals(1, CircuitList.countPendingClose())
        assertEquals(1, CircuitList.closeAllMarked())
        assertEquals(2, CircuitList.count())
        assertNull(CircuitList.get(1))
    }

    @Test
    fun `opened circuits cache`() {
        val m = CircuitList.registerOrigin(9, CircuitPurpose.GENERAL)
        (m.kind as CircuitKind.Origin).hasOpened = true
        assertTrue(CircuitList.anyOpenedCircuits())
        CircuitList.cacheOpenedCircuitState(true)
        assertTrue(CircuitList.anyOpenedCircuitsCached())
        CircuitList.cacheOpenedCircuitState(false)
        assertEquals(false, CircuitList.anyOpenedCircuitsCached())
    }
}
