package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.kotlintor.circuit.ConfluxCell
import org.kotlintor.circuit.ConfluxParams
import org.kotlintor.circuit.CongestionControlVegas
import org.kotlintor.config.TorConfig
import org.kotlintor.dir.Consensus
import org.kotlintor.dir.RouterStatus
import java.nio.file.Files
import java.time.Instant

/**
 * Elevates:
 * - L1:core/or/conflux_params.c
 * - L1:core/or/conflux_cell.c
 * - L1:core/or/congestion_control_vegas.c
 */
class ConfluxParamsCellVegasElevationTest {
    @BeforeEach
    fun reset() {
        ConfluxParams.resetToDefaults()
    }

    @Test
    fun `conflux_params defaults and prebuilt gating`() {
        val cfg = TorConfig(dataDirectory = Files.createTempDirectory("ktor-cfx"))
        assertTrue(ConfluxParams.isEnabled(cfg))
        assertEquals(10, ConfluxParams.getMaxLinkedSet())
        assertEquals(0, ConfluxParams.getMaxPrebuilt()) // no exits counted yet
        ConfluxParams.setExitConfluxRatioForTests(0.5)
        assertEquals(1, ConfluxParams.getMaxPrebuilt()) // below 0.60 threshold
        ConfluxParams.setExitConfluxRatioForTests(0.8)
        assertEquals(3, ConfluxParams.getMaxPrebuilt())
        assertEquals(2, ConfluxParams.getNumLegsSet())
        assertEquals(100, ConfluxParams.getSendPct())
    }

    @Test
    fun `conflux_params newConsensus`() {
        val now = Instant.parse("2024-01-01T00:00:00Z")
        val exitOk = RouterStatus(
            nickname = "Exit1",
            identity = ByteArray(20) { 1 },
            digest = ByteArray(20) { 2 },
            publication = now,
            ip = "1.2.3.4",
            orPort = 9001,
            dirPort = 0,
            flags = setOf("Exit", "Running", "Valid"),
            version = null,
            proto = mapOf("Conflux" to "1"),
            bandwidth = 1000,
        )
        val ns = Consensus(
            validAfter = now,
            freshUntil = now.plusSeconds(3600),
            validUntil = now.plusSeconds(7200),
            relays = listOf(exitOk),
            raw = "",
            params = mapOf(
                "cfx_enabled" to 1L,
                "cfx_max_linked_set" to 7L,
                "cfx_num_legs_set" to 3L,
            ),
        )
        ConfluxParams.newConsensus(ns)
        assertEquals(7, ConfluxParams.getMaxLinkedSet())
        assertEquals(3, ConfluxParams.getNumLegsSet())
        assertEquals(1.0, ConfluxParams.exitConfluxRatio(), 0.001)
        assertEquals(3, ConfluxParams.getMaxPrebuilt())
    }

    @Test
    fun `conflux_cell link switch roundtrip`() {
        val nonce = ConfluxCell.newNonce()
        val link = ConfluxCell.Link(
            nonce = nonce,
            lastSeqnoSent = 9,
            lastSeqnoRecv = 4,
            desiredUx = ConfluxCell.DesiredUx.HIGH_THROUGHPUT,
        )
        val parsed = ConfluxCell.parseLink(ConfluxCell.buildLink(link))
        assertTrue(parsed.nonce.contentEquals(nonce))
        assertEquals(9, parsed.lastSeqnoSent)
        assertEquals(4, parsed.lastSeqnoRecv)
        assertEquals(ConfluxCell.DesiredUx.HIGH_THROUGHPUT, parsed.desiredUx)
        assertEquals(0, ConfluxCell.buildLinkedAck().size)
        assertEquals(42L, ConfluxCell.parseSwitch(ConfluxCell.buildSwitch(42)).sequence)
    }

    @Test
    fun `congestion_control_vegas exit params and update`() {
        val p = CongestionControlVegas.exitParams(31)
        assertEquals(93, p.alpha)
        assertEquals(124, p.beta)
        assertEquals(155, p.delta)
        assertEquals(0, CongestionControlVegas.queueUse(100, 10, 10))
        assertEquals(50, CongestionControlVegas.queueUse(100, 50, 100))
        val ssExit = CongestionControlVegas.updateCwnd(
            cwnd = 124,
            queueUse = 200,
            inSlowStart = true,
            params = p,
            sendmeInc = 31,
        )
        assertFalse(ssExit.inSlowStart)
        assertEquals(93, ssExit.newCwnd) // 124 * 3/4
        val grow = CongestionControlVegas.updateCwnd(
            cwnd = 200,
            queueUse = 10,
            inSlowStart = false,
            params = p,
            sendmeInc = 31,
        )
        assertEquals(231, grow.newCwnd)
    }
}
