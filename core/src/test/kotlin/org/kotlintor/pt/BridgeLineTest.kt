package org.kotlintor.pt

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class BridgeLineTest {
    @Test
    fun `parse obfs4 bridge`() {
        val b = BridgeLine.parse(
            "obfs4 1.2.3.4:443 AABBCCDDEEFF00112233445566778899AABBCCDD cert=abc iat-mode=0",
        )!!
        assertEquals("obfs4", b.transport)
        assertEquals("1.2.3.4", b.host)
        assertEquals(443, b.port)
        assertEquals("AABBCCDDEEFF00112233445566778899AABBCCDD", b.fingerprintHex)
        assertEquals("abc", b.args["cert"])
    }

    @Test
    fun `parse vanilla bridge`() {
        val b = BridgeLine.parse("10.0.0.1:9001 DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF")!!
        assertNull(b.transport)
        assertEquals("10.0.0.1", b.host)
        assertEquals(9001, b.port)
    }
}
