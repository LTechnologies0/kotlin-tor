package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.kotlintor.circuit.CongestionControlCommon
import org.kotlintor.dir.Consensus
import org.kotlintor.link.ChannelPaddingController
import org.kotlintor.link.ChannelPaddingDecision
import org.kotlintor.link.ChannelPaddingParams
import org.kotlintor.link.PaddingNegotiate
import java.time.Instant

/**
 * Elevates:
 * - L1:core/or/channelpadding.c
 * - L1:core/or/congestion_control_common.c
 */
class ChannelPaddingCcCommonElevationTest {
    @BeforeEach
    fun reset() {
        CongestionControlCommon.resetToDefaults()
    }

    @Test
    fun `channelpadding decide schedule and send`() {
        val c = ChannelPaddingController(
            params = ChannelPaddingParams(itoLowMs = 100, itoHighMs = 100),
            hasCircuitUsage = true,
        )
        val t0 = 1_000_000L
        c.noteCellActivity(t0)
        assertEquals(ChannelPaddingDecision.PAD_LATER, c.decide(t0 + 50))
        assertEquals(ChannelPaddingDecision.PADDING_SCHEDULED, c.decide(t0 + 150))
        // with itoLow==itoHigh, scheduledAt == last+low ≤ now → next decide sends
        assertEquals(ChannelPaddingDecision.PADDING_SENT, c.decide(t0 + 150))
        c.applyNegotiate(PaddingNegotiate.COMMAND_STOP, 0, 0)
        assertEquals(ChannelPaddingDecision.WONT_PAD, c.decide(t0 + 10_000))
    }

    @Test
    fun `channelpadding consensus params`() {
        val p = ChannelPaddingParams.fromConsensus(
            mapOf("nf_ito_low" to 2000, "nf_pad_relays" to 0),
        )
        assertEquals(2000, p.itoLowMs)
        assertFalse(p.padRelays)
    }

    @Test
    fun `congestion_control_common enabled and consensus`() {
        assertTrue(CongestionControlCommon.enabled())
        assertEquals(31, CongestionControlCommon.current().sendmeInc)
        CongestionControlCommon.setAlgForTests(CongestionControlCommon.CC_ALG_SENDME)
        assertFalse(CongestionControlCommon.enabled())
        CongestionControlCommon.resetToDefaults()
        val now = Instant.parse("2024-06-01T00:00:00Z")
        CongestionControlCommon.newConsensus(
            Consensus(
                validAfter = now,
                freshUntil = now.plusSeconds(3600),
                validUntil = now.plusSeconds(7200),
                relays = emptyList(),
                raw = "",
                params = mapOf(
                    "cc_alg" to 2L,
                    "cc_sendme_inc" to 40L,
                    "cc_cwnd_init" to 160L,
                ),
            ),
        )
        assertTrue(CongestionControlCommon.enabled())
        assertEquals(40, CongestionControlCommon.current().sendmeInc)
        assertEquals(160, CongestionControlCommon.current().cwndInit)
    }
}
