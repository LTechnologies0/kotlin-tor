package org.kotlintor.circuit

import org.kotlintor.crypto.Cgo
import org.kotlintor.crypto.CgoHop

/**
 * CGO hop-layer crypt (C Tor `relay_crypto_cgo.c` / Prop359).
 *
 * Inventory: `L1:core/crypto/relay_crypto_cgo.c`
 *
 * Abstraction over tor1 [HopCrypto] and Prop359 [CgoHop] client layers.
 */
sealed interface HopLayer {
    /** Tag/digest for SENDME authentication (inbound / deliver path). */
    fun inboundSendmeTag(): ByteArray

    /** Tag/digest after originating outbound (package path / SENDME expect). */
    fun outboundSendmeTag(): ByteArray

    fun originateOutbound(cmd: Int, relayPayload: ByteArray): ByteArray

    fun forwardOutbound(cmd: Int, encrypted: ByteArray): ByteArray

    fun peelInbound(cmd: Int, encrypted: ByteArray): PeelResult
}

class Tor1HopLayer(private val crypto: HopCrypto) : HopLayer {
    override fun inboundSendmeTag(): ByteArray = crypto.inboundDigest()

    override fun outboundSendmeTag(): ByteArray = crypto.outboundDigest()

    override fun originateOutbound(cmd: Int, relayPayload: ByteArray): ByteArray =
        crypto.originateOutbound(relayPayload)

    override fun forwardOutbound(cmd: Int, encrypted: ByteArray): ByteArray =
        crypto.forwardOutbound(encrypted)

    override fun peelInbound(cmd: Int, encrypted: ByteArray): PeelResult =
        crypto.peelInbound(encrypted)
}

/**
 * Client-side CGO hop (Prop359): [forward] toward the network, [backward] from the network.
 */
class CgoClientHopLayer(
    private val forward: CgoHop,
    private val backward: CgoHop,
) : HopLayer {
    override fun inboundSendmeTag(): ByteArray = backward.tag.copyOf()

    override fun outboundSendmeTag(): ByteArray = forward.tag.copyOf()

    override fun originateOutbound(cmd: Int, relayPayload: ByteArray): ByteArray {
        // Prefer full V1 509-byte cell (tag‖cmd‖len‖…); legacy path packs V0 into M.
        val cell = when {
            relayPayload.size == Cgo.CELL_DATA_LEN -> relayPayload.copyOf()
            else -> toCgoCell(relayPayload)
        }
        forward.clientOriginate(cmd, cell)
        return cell
    }

    override fun forwardOutbound(cmd: Int, encrypted: ByteArray): ByteArray {
        require(encrypted.size == Cgo.CELL_DATA_LEN)
        val cell = encrypted.copyOf()
        forward.clientEncryptOutbound(cmd, cell)
        return cell
    }

    override fun peelInbound(cmd: Int, encrypted: ByteArray): PeelResult {
        require(encrypted.size == Cgo.CELL_DATA_LEN)
        val cell = encrypted.copyOf()
        val sendme = backward.clientDecryptInbound(cmd, cell)
        return if (sendme != null) {
            // Recognized: full 509-byte plaintext V1 cell (tag area + body).
            PeelResult(cell, true)
        } else {
            PeelResult(cell, false)
        }
    }

    companion object {
        fun fromSeeds(forwardSeed: ByteArray, backwardSeed: ByteArray): CgoClientHopLayer =
            CgoClientHopLayer(CgoHop.fromSeed(forwardSeed), CgoHop.fromSeed(backwardSeed))

        /**
         * Legacy: pack classic V0 509-byte relay payload into TAG‖M (M = first 493 bytes).
         * Prefer [RelayCell.toPayloadV1] for live CGO circuits.
         */
        fun toCgoCell(relayPayload: ByteArray): ByteArray {
            val cell = ByteArray(Cgo.CELL_DATA_LEN)
            val mLen = minOf(relayPayload.size, Cgo.PAYLOAD_LEN)
            relayPayload.copyInto(cell, Cgo.TAG_LEN, 0, mLen)
            return cell
        }
    }
}

/**
 * Relay-side CGO crypt state for one circuit hop facing the client.
 */
class CgoRelayHopLayer(
    private val decryptFromClient: CgoHop,
    private val encryptToClient: CgoHop,
) {
    fun decryptFromClient(cmd: Int, cell: ByteArray): ByteArray? {
        require(cell.size == Cgo.CELL_DATA_LEN)
        return decryptFromClient.relayDecryptOutbound(cmd, cell)
    }

    fun originateToClient(cmd: Int, relayPayload: ByteArray): ByteArray {
        val cell = when {
            relayPayload.size == Cgo.CELL_DATA_LEN -> relayPayload.copyOf()
            else -> CgoClientHopLayer.toCgoCell(relayPayload)
        }
        encryptToClient.relayOriginate(cmd, cell)
        return cell
    }

    fun encryptToClient(cmd: Int, cell: ByteArray) {
        encryptToClient.relayEncryptInbound(cmd, cell)
    }

    companion object {
        /** Client Sf|Sb → relay uses swapped directions. */
        fun fromClientSeeds(forwardSeed: ByteArray, backwardSeed: ByteArray): CgoRelayHopLayer =
            CgoRelayHopLayer(
                decryptFromClient = CgoHop.fromSeed(forwardSeed),
                encryptToClient = CgoHop.fromSeed(backwardSeed),
            )
    }
}
