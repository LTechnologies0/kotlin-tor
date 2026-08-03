package org.kotlintor.pow

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class HashXVectorTest {
    @Test
    fun `hashx size8 vectors from tevador tests`() {
        val seed = "This is a test".toByteArray(Charsets.US_ASCII) + byteArrayOf(0)
        val hx = HashX()
        assertTrue(hx.make(seed))
        val out = ByteArray(8)
        hx.exec(123456L, out)
        assertEquals("aebdd50aa67c93af", out.joinToString("") { "%02x".format(it) })
        hx.exec(0L, out)
        assertEquals("2b2f54567dcbea98", out.joinToString("") { "%02x".format(it) })
    }
}
