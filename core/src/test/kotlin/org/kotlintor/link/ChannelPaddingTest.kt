package org.kotlintor.link

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ChannelPaddingTest {
    @Test
    fun `idle below ito does not pad`() {
        val c = ChannelPaddingController(ChannelPaddingParams(itoLowMs = 1_000, itoHighMs = 2_000))
        c.noteCellActivity(nowMs = 0)
        assertEquals(ChannelPaddingDecision.PAD_LATER, c.decide(nowMs = 500))
    }

    @Test
    fun `idle schedules then sends`() {
        val c = ChannelPaddingController(ChannelPaddingParams(itoLowMs = 100, itoHighMs = 100))
        c.noteCellActivity(nowMs = 0)
        assertEquals(ChannelPaddingDecision.PADDING_SCHEDULED, c.decide(nowMs = 150))
        assertEquals(ChannelPaddingDecision.PADDING_SENT, c.decide(nowMs = 150))
    }

    @Test
    fun `stop negotiate disables`() {
        val c = ChannelPaddingController()
        c.applyNegotiate(PaddingNegotiate.COMMAND_STOP, 0, 0)
        assertEquals(ChannelPaddingDecision.WONT_PAD, c.decide())
    }

    @Test
    fun `consensus params parse`() {
        val p = ChannelPaddingParams.fromConsensus(mapOf("nf_ito_low" to 2000, "nf_ito_high" to 8000))
        assertEquals(2000, p.itoLowMs)
        assertTrue(p.padRelays)
    }
}
