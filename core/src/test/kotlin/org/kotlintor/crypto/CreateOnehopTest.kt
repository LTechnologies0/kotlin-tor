package org.kotlintor.crypto

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.kotlintor.circuit.CircuitExtensions

class CreateOnehopTest {
    @Test
    fun `client and server derive identical keystream`() {
        val cm = CircuitExtensions.ccRequest()
        val (state, req) = CreateOnehop.clientBegin(cm)
        assertEquals(32 + cm.size, req.size)

        val (resp, serverKs) = CreateOnehop.serverRespond(
            req,
            serverExtensions = CircuitExtensions.ccResponse(31),
        )
        val client = CreateOnehop.clientFinish(state, resp)
        assertArrayEquals(serverKs, client.keystream)
        assertEquals(31, CircuitExtensions.sendmeIncOrNull(client.serverMessage))
        assertEquals(CreateOnehop.HTYPE, 4)
    }
}
