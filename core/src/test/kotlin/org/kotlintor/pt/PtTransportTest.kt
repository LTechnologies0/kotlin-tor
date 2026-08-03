package org.kotlintor.pt

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PtTransportTest {
    @Test
    fun `parse known transports`() {
        assertEquals(PtTransport.OBFS4, PtTransport.parse("obfs4"))
        assertEquals(PtTransport.SNOWFLAKE, PtTransport.parse("snowflake"))
        assertEquals(PtTransport.MEEK_LITE, PtTransport.parse("meek_lite"))
    }

    @Test
    fun `obfs4 requires cert`() {
        val missing = PtBridgeArgs.requiredPresent(PtTransport.OBFS4, emptyMap())
        assertTrue(missing.any { it.contains("cert") })
        val ok = PtBridgeArgs.requiredPresent(PtTransport.OBFS4, mapOf("cert" to "abcd", "iat-mode" to "0"))
        assertTrue(ok.isEmpty())
    }

    @Test
    fun `parseArgs from bridge line`() {
        val args = PtBridgeArgs.parseArgs(
            "obfs4 1.2.3.4:443 FINGERPRINT cert=abcd iat-mode=0",
        )
        assertEquals("abcd", args["cert"])
        assertEquals("0", args["iat-mode"])
    }

    @Test
    fun `meek sample bridge line`() {
        val line = MeekConfig.sampleBridgeLine("1.2.3.4:443", "ABCD")
        assertTrue(line.startsWith("meek_lite "))
        assertTrue(line.contains("url="))
        assertTrue(line.contains("front="))
    }
}
