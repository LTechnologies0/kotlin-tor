package org.kotlintor.pow

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class EquiXVectorTest {
    @Test
    fun `verify C sol0 by index hex`() {
        val chal = "kotlin-tor-equix-seed".toByteArray(Charsets.US_ASCII)
        val sol = EquiXSolution.fromIndexHex("6b6f79bc7faaa5e756f4b9e165b4de64")
        assertEquals(EquiXResult.OK, EquiX.verify(chal, sol))
    }

    @Test
    fun `solve finds C sol0`() {
        val chal = "kotlin-tor-equix-seed".toByteArray(Charsets.US_ASCII)
        val sols = EquiX.solve(chal)
        assertTrue(sols.isNotEmpty(), "no solutions")
        val hexes = sols.map { it.toIndexHex() }.toSet()
        assertTrue("6b6f79bc7faaa5e756f4b9e165b4de64" in hexes, "got $hexes")
        for (s in sols) assertTrue(EquiX.verifyOk(chal, s))
    }
}
