package org.kotlintor.circuit

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.cell.RelayCommand

class HopCryptoTest {
    @Test
    fun `originate then peel recognizes`() {
        val client = HopCrypto.legacy(ByteArray(20) { 1 }, ByteArray(20) { 2 }, ByteArray(16) { 3 }, ByteArray(16) { 4 })
        val relay = HopCrypto.legacy(ByteArray(20) { 2 }, ByteArray(20) { 1 }, ByteArray(16) { 4 }, ByteArray(16) { 3 })
        val cell = buildRelayCell(RelayCommand.DATA, 1, "hi".toByteArray())
        val enc = client.originateOutbound(cell.toPayload())
        val peel = relay.peelInbound(enc)
        assertTrue(peel.recognized)
        assertEquals("hi", org.kotlintor.cell.RelayCell.parse(peel.payload).data.decodeToString())
    }

    @Test
    fun `layer cake encrypts multi-hop without throwing`() {
        val cake = CircuitLayerCake()
        cake.addHop(HopCrypto.legacy(ByteArray(20) { 1 }, ByteArray(20) { 2 }, ByteArray(16) { 3 }, ByteArray(16) { 4 }))
        cake.addHop(HopCrypto.legacy(ByteArray(20) { 5 }, ByteArray(20) { 6 }, ByteArray(16) { 7 }, ByteArray(16) { 8 }))
        val enc = cake.encryptRelay(buildRelayCell(RelayCommand.EXTEND2, 0, ByteArray(80) { 9 }))
        assertEquals(509, enc.size)
        val enc2 = cake.encryptRelay(buildRelayCell(RelayCommand.BEGIN, 1, "x".toByteArray()))
        assertEquals(509, enc2.size)
    }
}
