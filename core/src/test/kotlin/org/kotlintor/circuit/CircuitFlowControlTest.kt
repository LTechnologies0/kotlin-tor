package org.kotlintor.circuit

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class CircuitFlowControlTest {
    @Test
    fun `SENDME every 100 inbound DATA cells`() = runBlocking {
        val flow = CircuitFlowControl()
        val dig = ByteArray(20) { 7 }
        repeat(99) {
            assertNull(flow.onInboundData(dig))
        }
        val body = flow.onInboundData(dig)
        assertNotNull(body)
        assertEquals(1, body!![0].toInt())
        assertEquals(20, body[2].toInt())
        assertEquals(23, body.size)
    }
}
