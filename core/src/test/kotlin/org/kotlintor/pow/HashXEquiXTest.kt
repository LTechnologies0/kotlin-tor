package org.kotlintor.pow

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class HashXEquiXTest {
    @Test
    fun `hashx size8 golden vectors`() {
        val seed = "This is a test".toByteArray(Charsets.US_ASCII) + byteArrayOf(0)
        val hx = HashX()
        assertTrue(hx.make(seed))
        val out = ByteArray(8)
        hx.exec(123456L, out)
        assertEquals("aebdd50aa67c93af", out.toHex())
        hx.exec(0L, out)
        assertEquals("2b2f54567dcbea98", out.toHex())
    }

    @Test
    fun `equix golden challenge kotlin-tor-equix-seed`() {
        val chal = "kotlin-tor-equix-seed".toByteArray(Charsets.US_ASCII)
        val sols = EquiX.solve(chal)
        assertEquals(4, sols.size)
        assertEquals("6b6f79bc7faaa5e756f4b9e165b4de64", sols[0].toIndexHex())
        assertEquals("66b69ab67afec633cc3dd98c5219e057", sols[1].toIndexHex())
        assertEquals("1b743b9772c57b4e486c9bbd836eff8b", sols[2].toIndexHex())
        assertEquals("2a4499f873fea6946d79b5fc54d0ba4a", sols[3].toIndexHex())
        for (s in sols) {
            assertTrue(EquiX.verifyOk(chal, s))
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
