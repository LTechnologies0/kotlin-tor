package org.kotlintor.circuit

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
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

    @Test
    fun `inbound SENDME rejected without matching digest`() = runBlocking {
        val flow = CircuitFlowControl()
        val q = Sendme.DigestQueue()
        val fake = Sendme.buildCellPayloadV1(ByteArray(20) { 1 })
        assertFalse(flow.onInboundSendme(fake, q))
    }

    @Test
    fun `inbound SENDME credited when digest matches`() = runBlocking {
        val flow = CircuitFlowControl(packageWindow = 100, increment = 100)
        val q = Sendme.DigestQueue()
        val tag = ByteArray(20) { 9 }
        // Exhaust window so credit is observable via beforeOutboundData returning.
        repeat(100) {
            val record = flow.beforeOutboundData()
            if (record) q.record(tag)
        }
        val good = Sendme.buildCellPayloadV1(tag)
        assertTrue(flow.onInboundSendme(good, q))
        // Window restored — next package must not hang.
        flow.beforeOutboundData()
    }
}
