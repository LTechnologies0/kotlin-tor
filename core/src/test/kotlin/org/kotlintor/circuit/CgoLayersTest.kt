package org.kotlintor.circuit

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.cell.RelayCell
import org.kotlintor.cell.RelayCommand
import org.kotlintor.crypto.CgoHop
import org.kotlintor.util.SecureRandomSource

class CgoLayersTest {
    @Test
    fun `client CGO hop round-trip V1 recognized`() {
        val sf = SecureRandomSource.nextBytes(80)
        val sb = SecureRandomSource.nextBytes(80)
        val client = CgoClientHopLayer.fromSeeds(sf, sb)
        val relay = CgoRelayHopLayer.fromClientSeeds(sf, sb)

        val clear = RelayCell.build(RelayCommand.DATA, 7, "hello-cgo".toByteArray()).toPayloadV1(pad = false)
        val cellCmd = org.kotlintor.cell.CellCommand.RELAY.id
        val enc = client.originateOutbound(cellCmd, clear)
        assertEquals(509, enc.size)

        val copy = enc.copyOf()
        val sendme = relay.decryptFromClient(cellCmd, copy)
        assertNotNull(sendme)
        val parsed = RelayCell.parseV1(copy)
        assertEquals(RelayCommand.DATA, parsed.command)
        assertEquals(7, parsed.streamId)
        assertEquals("hello-cgo", parsed.data.decodeToString())

        val cake = CircuitLayerCake()
        cake.addCgoHop(client)
        assertTrue(cake.cgo)
        assertEquals(1, cake.hopCount)
    }

    @Test
    fun `CircuitLayerCake CGO V1 EXTEND2 encrypt then relay decrypt`() {
        val sf = SecureRandomSource.nextBytes(80)
        val sb = SecureRandomSource.nextBytes(80)
        val cake = CircuitLayerCake().also { it.addCgoHop(CgoClientHopLayer.fromSeeds(sf, sb)) }
        val body = ByteArray(48) { (it * 3).toByte() }
        val cellCmd = org.kotlintor.cell.CellCommand.RELAY_EARLY.id
        val enc = cake.encryptRelay(RelayCell.build(RelayCommand.EXTEND2, 0, body), cellCmd)

        val relay = CgoRelayHopLayer.fromClientSeeds(sf, sb)
        val plain = enc.copyOf()
        assertNotNull(relay.decryptFromClient(cellCmd, plain))
        val parsed = RelayCell.parseV1(plain)
        assertEquals(RelayCommand.EXTEND2, parsed.command)
        assertEquals(0, parsed.streamId)
        assertArrayEquals(body, parsed.data)
    }

    @Test
    fun `CircuitLayerCake CGO V1 decrypt inbound from relay`() {
        val sf = SecureRandomSource.nextBytes(80)
        val sb = SecureRandomSource.nextBytes(80)
        val cake = CircuitLayerCake().also { it.addCgoHop(CgoClientHopLayer.fromSeeds(sf, sb)) }
        val relay = CgoRelayHopLayer.fromClientSeeds(sf, sb)
        val body = "extended-ok".toByteArray()
        val cellCmd = org.kotlintor.cell.CellCommand.RELAY.id
        val v1 = RelayCell.build(RelayCommand.EXTENDED2, 0, body).toPayloadV1(pad = false)
        val towardClient = relay.originateToClient(cellCmd, v1)
        val decoded = cake.decryptRelay(towardClient, cellCmd)
        assertNotNull(decoded)
        assertEquals(0, decoded!!.first)
        assertEquals(RelayCommand.EXTENDED2, decoded.second.command)
        assertArrayEquals(body, decoded.second.data)
    }

    @Test
    fun `fromSeed rejects wrong length`() {
        org.junit.jupiter.api.assertThrows<IllegalArgumentException> {
            CgoHop.fromSeed(ByteArray(16))
        }
    }
}
