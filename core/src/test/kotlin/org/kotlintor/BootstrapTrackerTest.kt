package org.kotlintor

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BootstrapTrackerTest {
    @Test
    fun `each advance notifies with progress and summary`() {
        val lines = ArrayList<String>()
        val t = BootstrapTracker { lines += it }
        t.notifyCurrent("Starting")
        t.advance(BootstrapPhase.CONN_DIR, summary = "Connecting to directory authority")
        t.advance(BootstrapPhase.REQUESTING_STATUS, summary = "Fetching ns consensus")
        t.advance(BootstrapPhase.LOADING_STATUS, summary = "Loaded consensus: 7000 relays")
        t.advance(BootstrapPhase.DONE, summary = "Done — circuit via a,b,c")
        assertEquals(5, lines.size)
        assertTrue(lines[0].contains("PROGRESS=0") && lines[0].contains("starting"))
        assertTrue(lines[1].contains("PROGRESS=5") && lines[1].contains("directory authority"))
        assertTrue(lines[2].contains("PROGRESS=15") && lines[2].contains("ns consensus"))
        assertTrue(lines[3].contains("PROGRESS=20") && lines[3].contains("7000 relays"))
        assertTrue(lines[4].contains("PROGRESS=100") && lines[4].contains("circuit via a,b,c"))
        assertEquals(100, t.phase.value.progress)
    }

    @Test
    fun `does not go backwards but forceNotify can re-emit`() {
        val lines = ArrayList<String>()
        val t = BootstrapTracker { lines += it }
        t.advance(BootstrapPhase.CIRCUIT_CREATE)
        lines.clear()
        t.advance(BootstrapPhase.CONN_OR, summary = "retry guard", forceNotify = true)
        assertEquals(1, lines.size)
        assertTrue(lines[0].contains("conn_or"))
        assertEquals(BootstrapPhase.CIRCUIT_CREATE, t.phase.value)
    }
}
