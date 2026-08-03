package org.kotlintor.circuit

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class ConfluxTest {
    @Test
    fun `link payload roundtrip`() {
        val nonce = Conflux.newNonce()
        val p = Conflux.LinkPayload(
            nonce = nonce,
            lastSeqnoSent = 7,
            lastSeqnoRecv = 3,
            desiredUx = Conflux.DesiredUx.HIGH_THROUGHPUT,
        )
        val parsed = Conflux.parseLink(p.encode())
        assertArrayEquals(nonce, parsed.nonce)
        assertEquals(7, parsed.lastSeqnoSent)
        assertEquals(3, parsed.lastSeqnoRecv)
        assertEquals(Conflux.DesiredUx.HIGH_THROUGHPUT, parsed.desiredUx)
    }

    @Test
    fun `switch payload`() {
        val s = Conflux.parseSwitch(Conflux.switchCell(99))
        assertEquals(99, s.sequnce)
    }
}
