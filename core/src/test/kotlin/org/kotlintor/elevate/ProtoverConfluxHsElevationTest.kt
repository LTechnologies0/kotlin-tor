package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.kotlintor.circuit.CircuitMuxEwma
import org.kotlintor.circuit.ConfluxCell
import org.kotlintor.circuit.ConfluxPool
import org.kotlintor.circuit.ConfluxUtil
import org.kotlintor.circuit.RelayCryptoTor1
import org.kotlintor.crypto.CreateFast
import org.kotlintor.dir.Protover
import org.kotlintor.hs.HsNtor

/**
 * Elevates:
 * - L1:core/or/protover.c
 * - L1:core/or/conflux_util.c
 * - L1:core/or/conflux_pool.c
 * - L1:core/crypto/relay_crypto_tor1.c
 * - L1:core/or/circuitmux_ewma.c
 * - L1:core/crypto/hs_ntor.c (evidence via HsNtor.hsMac + introduce)
 */
class ProtoverConfluxHsElevationTest {
    @BeforeEach
    fun reset() {
        ConfluxPool.freeAll()
        ConfluxPool.init()
        org.kotlintor.circuit.ConfluxParams.resetToDefaults()
    }

    @Test
    fun `protover supported list and parse`() {
        val all = Protover.getSupportedProtocols()
        assertTrue(all.contains("Relay="))
        assertTrue(Protover.supports(Protover.ProtocolType.FLOW_CTRL, 2))
        assertTrue(Protover.supports(Protover.ProtocolType.CONFLUX, 1))
        assertFalse(Protover.supports(Protover.ProtocolType.RELAY, 99))
        assertTrue(
            Protover.listSupportsProtocolOrLater(
                "Relay=1-4",
                Protover.ProtocolType.RELAY,
                3,
            ),
        )
        assertEquals("1-6", Protover.getSupported(Protover.ProtocolType.RELAY))
    }

    @Test
    fun `conflux_util can_send validate legs`() {
        val set = ConfluxUtil.SetState(nonce = ConfluxCell.newNonce())
        assertFalse(ConfluxUtil.canSend(set))
        ConfluxUtil.addLeg(set, 1)
        ConfluxUtil.addLeg(set, 2)
        ConfluxUtil.noteRtt(set, 1, 40)
        ConfluxUtil.noteRtt(set, 2, 20)
        assertTrue(ConfluxUtil.validateLegs(set))
        assertTrue(ConfluxUtil.canSend(set))
        assertEquals(2L, ConfluxUtil.decideNextCirc(set))
        assertEquals(20L, ConfluxUtil.getCircRtt(set, 2))
    }

    @Test
    fun `conflux_pool init chooseAlgorithm markLinked`() {
        assertTrue(ConfluxPool.isInitialized())
        assertEquals(ConfluxPool.ALG_LOWRTT, ConfluxPool.chooseAlgorithm(ConfluxCell.DesiredUx.NO_OPINION))
        assertEquals(ConfluxPool.ALG_MINRTT, ConfluxPool.chooseAlgorithm(ConfluxCell.DesiredUx.MIN_LATENCY))
        val set = ConfluxPool.newSet()
        ConfluxUtil.addLeg(set, 10)
        assertEquals(1, ConfluxPool.unlinkedCount())
        ConfluxPool.markLinked(set)
        assertEquals(1, ConfluxPool.linkedCount())
        assertEquals(0, ConfluxPool.unlinkedCount())
        assertNotNull(ConfluxPool.find(set.nonce))
        ConfluxPool.markAllForClose(set.nonce)
        assertEquals(0, ConfluxPool.linkedCount())
    }

    @Test
    fun `relay_crypto_tor1 from create_fast`() {
        val (st, x) = CreateFast.clientBegin()
        val (hs, _) = CreateFast.serverRespond(x)
        val keys = CreateFast.clientFinish(st, hs)
        val hop = RelayCryptoTor1.fromCreateFast(keys)
        val payload = ByteArray(509) { 0 }
        payload[0] = 2
        assertTrue(RelayCryptoTor1.roundTripRecognized(hop, payload))
    }

    @Test
    fun `circuitmux_ewma scale and consensus`() {
        val scale = CircuitMuxEwma.computeScale(30.0, 10)
        assertTrue(scale in 0.01..0.99)
        val p = CircuitMuxEwma.fromConsensus(mapOf("CircuitPriorityHalflifeMsec" to 15_000L))
        assertEquals(15.0, p.halfLifeSec, 0.001)
    }

    @Test
    fun `hs_ntor mac surface`() {
        val mac = HsNtor.hsMac("who".toByteArray(), "knows?".toByteArray())
        assertEquals(32, mac.size)
        assertEquals(HsNtor.S_KEY_LEN, 32)
    }
}
