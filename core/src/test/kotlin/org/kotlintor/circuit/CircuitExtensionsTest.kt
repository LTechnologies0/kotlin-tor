package org.kotlintor.circuit

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CircuitExtensionsTest {
    @Test
    fun `round trip CC request and response`() {
        val req = CircuitExtensions.ccRequest()
        assertTrue(CircuitExtensions.clientRequestedCc(req))
        assertEquals(0, CircuitExtensions.decode(req).single().body.size)

        val resp = CircuitExtensions.ccResponse(31)
        assertEquals(31, CircuitExtensions.sendmeIncOrNull(resp))
        assertNull(CircuitExtensions.sendmeIncOrNull(byteArrayOf(0)))
    }

    @Test
    fun `empty extensions`() {
        assertEquals(0, CircuitExtensions.decode(byteArrayOf(0)).size)
        assertEquals(1, CircuitExtensions.encode(emptyList()).size)
    }

    @Test
    fun `subproto request is binary protocol_id plus cap`() {
        // tor-spec: Relay=6 → [0x02, 0x06]
        val body = CircuitExtensions.subprotoRequest(
            listOf(CircuitExtensions.ProtoReq("Relay", CircuitExtensions.RELAY_CRYPT_CGO)),
        )
        val ext = CircuitExtensions.decode(body).single()
        assertEquals(CircuitExtensions.SUBPROTO_REQUEST, ext.type)
        assertArrayEquals(byteArrayOf(0x02, 0x06), ext.body)
        val reqs = CircuitExtensions.decodeSubprotoRequest(ext.body)
        assertEquals(1, reqs.size)
        assertEquals("Relay", reqs[0].name)
        assertEquals(6, reqs[0].version)
        assertTrue(CircuitExtensions.clientRequestedCgo(body))
    }

    @Test
    fun `cgo helper encodes Relay equals 6`() {
        val enc = CircuitExtensions.encode(listOf(CircuitExtensions.cgoSubprotoRequest()))
        assertTrue(CircuitExtensions.clientRequestedCgo(enc))
        assertFalse(CircuitExtensions.clientRequestedCc(enc))
    }

    @Test
    fun `legacy ascii subproto still decodes`() {
        val ascii = "Relay=6".toByteArray(Charsets.US_ASCII)
        val reqs = CircuitExtensions.decodeSubprotoRequest(ascii)
        assertEquals(1, reqs.size)
        assertEquals("Relay", reqs[0].name)
        assertEquals(6, reqs[0].version)
    }
}
