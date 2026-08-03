package org.kotlintor.circuit

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CongestionControlTest {
    @Test
    fun `SENDME every sendme_inc inbound DATA`() = runBlocking {
        val cc = CongestionControl(sendmeInc = 31)
        val dig = ByteArray(20) { 3 }
        repeat(30) { assertNull(cc.onInboundData(dig)) }
        assertNotNull(cc.onInboundData(dig))
    }

    @Test
    fun `package window tracks cwnd and SENDME credit`() = runBlocking {
        val cc = CongestionControl(sendmeInc = 10, cwnd = 20, cwndMin = 10)
        repeat(20) { cc.beforeOutboundData() }
        assertEquals(20, cc.inFlight)
        // Acquiring one more would block — credit via SENDME first.
        cc.onInboundSendme()
        assertTrue(cc.inFlight <= 20)
        assertTrue(cc.congestionWindow >= 10)
        cc.beforeOutboundData()
        assertEquals(cc.inFlight, 20 - 10 + 1)
    }

    @Test
    fun `negotiated sendme_inc scales windows`() {
        val cc = CongestionControl.fromNegotiatedSendmeInc(31)
        assertEquals(31, cc.increment)
        assertEquals(124, cc.congestionWindow)
    }
}
