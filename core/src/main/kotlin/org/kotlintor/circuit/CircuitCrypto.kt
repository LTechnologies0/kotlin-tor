package org.kotlintor.circuit

import org.kotlintor.cell.RelayCell
import org.kotlintor.cell.RelayCommand
import org.kotlintor.crypto.AesCtr
import org.kotlintor.crypto.Ntor
import org.kotlintor.crypto.RunningSha1
import org.kotlintor.crypto.RunningSha3
import org.kotlintor.hs.HsNtor

data class PeelResult(val payload: ByteArray, val recognized: Boolean)

private interface RunningDigest {
    fun update(data: ByteArray, offset: Int = 0, length: Int = data.size - offset)
    fun peek(): ByteArray
    fun preview(extra: ByteArray): ByteArray
}

private class Sha1Running(seed: ByteArray) : RunningDigest {
    private val d = RunningSha1().also { it.update(seed) }
    override fun update(data: ByteArray, offset: Int, length: Int) = d.update(data, offset, length)
    override fun peek(): ByteArray = d.peek()
    override fun preview(extra: ByteArray): ByteArray = d.preview(extra)
}

private class Sha3Running(seed: ByteArray) : RunningDigest {
    private val d = RunningSha3().also { it.update(seed) }
    override fun update(data: ByteArray, offset: Int, length: Int) = d.update(data, offset, length)
    override fun peek(): ByteArray = d.peek()
    override fun preview(extra: ByteArray): ByteArray = d.preview(extra)
}

/**
 * Per-hop relay crypto (tor1: AES-CTR + running digest).
 * Clearnet hops: AES-128 + SHA1. HS v3 virtual hop: AES-256 + SHA3-256.
 *
 * Client outbound:
 * - Destination hop: set digest, then encrypt ([originateOutbound])
 * - Intermediate hops: encrypt only ([forwardOutbound]) — no digest update
 */
class HopCrypto private constructor(
    private val fwdDigest: RunningDigest,
    private val backDigest: RunningDigest,
    forwardKey: ByteArray,
    backwardKey: ByteArray,
) {
    private val fwdCipher = AesCtr(forwardKey)
    private val backCipher = AesCtr(backwardKey)

    /** Running digest after the last recognized inbound cell (SENDME v1). */
    fun inboundDigest(): ByteArray = backDigest.peek()

    /** Destination hop: authenticate + encrypt. */
    fun originateOutbound(relayPayload: ByteArray): ByteArray {
        val work = relayPayload.copyOf()
        work.fill(0, 5, 9)
        fwdDigest.update(work)
        fwdDigest.peek().copyInto(work, 5, 0, 4)
        return fwdCipher.process(work)
    }

    /** Intermediate hop: encrypt only (no digest). */
    fun forwardOutbound(relayPayload: ByteArray): ByteArray =
        fwdCipher.process(relayPayload)

    fun peelInbound(encrypted: ByteArray): PeelResult {
        val plain = backCipher.process(encrypted)
        val recognizedField = ((plain[1].toInt() and 0xff) shl 8) or (plain[2].toInt() and 0xff)
        if (recognizedField != 0) {
            return PeelResult(plain, false)
        }
        val digestField = plain.copyOfRange(5, 9)
        val work = plain.copyOf()
        work.fill(0, 5, 9)
        val expect = backDigest.preview(work).copyOfRange(0, 4)
        val isRecognized = expect.contentEquals(digestField)
        if (isRecognized) {
            backDigest.update(work)
        }
        return PeelResult(plain, isRecognized)
    }

    companion object {
        /** Legacy tor1 hop (AES-128 + SHA1). */
        fun legacy(
            forwardDigestSeed: ByteArray,
            backwardDigestSeed: ByteArray,
            forwardKey: ByteArray,
            backwardKey: ByteArray,
        ): HopCrypto =
            HopCrypto(
                Sha1Running(forwardDigestSeed),
                Sha1Running(backwardDigestSeed),
                forwardKey,
                backwardKey,
            )

        fun fromNtor(result: Ntor.Result): HopCrypto =
            legacy(
                result.forwardDigest,
                result.backwardDigest,
                result.forwardKey,
                result.backwardKey,
            )

        fun fromCreateFast(result: org.kotlintor.crypto.CreateFast.Result): HopCrypto =
            legacy(
                result.forwardDigest,
                result.backwardDigest,
                result.forwardKey,
                result.backwardKey,
            )

        /**
         * ntor-v3 KEYSTREAM partition (same layout as ntor):
         * Df(20)|Db(20)|Kf(16)|Kb(16)|KH(20).
         */
        fun fromNtorV3Keystream(keystream: ByteArray): HopCrypto {
            require(keystream.size >= 72) { "ntor-v3 keystream too short" }
            return legacy(
                keystream.copyOfRange(0, 20),
                keystream.copyOfRange(20, 40),
                keystream.copyOfRange(40, 56),
                keystream.copyOfRange(56, 72),
            )
        }

        fun khFromNtorV3Keystream(keystream: ByteArray): ByteArray {
            require(keystream.size >= 92)
            return keystream.copyOfRange(72, 92)
        }

        fun fromHsNtor(keys: HsNtor.HopKeyMaterial): HopCrypto =
            HopCrypto(
                Sha3Running(keys.forwardDigest),
                Sha3Running(keys.backwardDigest),
                keys.forwardKey,
                keys.backwardKey,
            )
    }
}

class CircuitLayerCake {
    private val hops = mutableListOf<HopLayer>()
    var cgo: Boolean = false
        private set

    fun addHop(hop: HopCrypto) {
        require(!cgo || hops.isEmpty()) { "cannot mix tor1 into CGO cake" }
        hops += Tor1HopLayer(hop)
    }

    fun addCgoHop(layer: CgoClientHopLayer) {
        if (hops.isEmpty()) cgo = true
        require(cgo) { "cannot mix CGO into tor1 cake" }
        hops += layer
    }

    fun inboundDigestAt(hopIndex: Int): ByteArray = hops[hopIndex].inboundSendmeTag()

    val hopCount: Int get() = hops.size

    fun encryptRelay(cell: RelayCell, cellCommand: Int = org.kotlintor.cell.CellCommand.RELAY.id): ByteArray {
        require(hops.isNotEmpty())
        // Prop359 / C Tor relay_crypto_cgo.c: UIV AD is the *cell* command (RELAY=3 or RELAY_EARLY=9),
        // not the inner RelayCommand (EXTEND2/DATA/…).
        val cmd = cellCommand
        // CGO circuits use RELAY_CELL_FORMAT_V1 (circuitbuild.c client_circ_negotiation_message).
        var payload = if (cgo) cell.toPayloadV1() else cell.toPayload()
        payload = hops.last().originateOutbound(cmd, payload)
        for (i in hops.size - 2 downTo 0) {
            payload = hops[i].forwardOutbound(cmd, payload)
        }
        return payload
    }

    fun decryptRelay(
        payload: ByteArray,
        cellCommand: Int = org.kotlintor.cell.CellCommand.RELAY.id,
    ): Pair<Int, RelayCell>? {
        var current = payload
        val cmd = cellCommand
        for (i in hops.indices) {
            val peel = hops[i].peelInbound(cmd, current)
            if (peel.recognized) {
                val relay = if (cgo) RelayCell.parseV1(peel.payload) else RelayCell.parse(peel.payload)
                return i to relay
            }
            current = peel.payload
        }
        return null
    }
}

fun buildCreate2Payload(htype: Int, handshake: ByteArray): ByteArray {
    val out = ByteArray(2 + 2 + handshake.size)
    out[0] = ((htype ushr 8) and 0xff).toByte()
    out[1] = (htype and 0xff).toByte()
    out[2] = ((handshake.size ushr 8) and 0xff).toByte()
    out[3] = (handshake.size and 0xff).toByte()
    handshake.copyInto(out, 4)
    return out
}

fun parseCreated2Payload(payload: ByteArray): ByteArray {
    val hlen = ((payload[0].toInt() and 0xff) shl 8) or (payload[1].toInt() and 0xff)
    return payload.copyOfRange(2, 2 + hlen)
}

fun buildExtend2Data(
    linkSpecifiers: List<ByteArray>,
    htype: Int,
    handshake: ByteArray,
): ByteArray {
    val parts = ArrayList<Byte>()
    parts += linkSpecifiers.size.toByte()
    for (ls in linkSpecifiers) {
        for (b in ls) parts += b
    }
    parts += ((htype ushr 8) and 0xff).toByte()
    parts += (htype and 0xff).toByte()
    parts += ((handshake.size ushr 8) and 0xff).toByte()
    parts += (handshake.size and 0xff).toByte()
    for (b in handshake) parts += b
    return parts.toByteArray()
}

fun ipv4LinkSpecifier(address: ByteArray, port: Int): ByteArray {
    require(address.size == 4)
    val out = ByteArray(8)
    out[0] = 0
    out[1] = 6
    address.copyInto(out, 2)
    out[6] = ((port ushr 8) and 0xff).toByte()
    out[7] = (port and 0xff).toByte()
    return out
}

fun legacyIdLinkSpecifier(fingerprint: ByteArray): ByteArray {
    require(fingerprint.size == 20)
    val out = ByteArray(22)
    out[0] = 2
    out[1] = 20
    fingerprint.copyInto(out, 2)
    return out
}

fun ed25519IdLinkSpecifier(ed: ByteArray): ByteArray {
    require(ed.size == 32)
    val out = ByteArray(34)
    out[0] = 3
    out[1] = 32
    ed.copyInto(out, 2)
    return out
}

fun buildBeginPayload(address: String, port: Int, flags: Int = 0): ByteArray {
    val s = "$address:$port\u0000"
    val bytes = s.toByteArray()
    val out = ByteArray(bytes.size + 4)
    bytes.copyInto(out)
    out[bytes.size] = ((flags ushr 24) and 0xff).toByte()
    out[bytes.size + 1] = ((flags ushr 16) and 0xff).toByte()
    out[bytes.size + 2] = ((flags ushr 8) and 0xff).toByte()
    out[bytes.size + 3] = (flags and 0xff).toByte()
    return out
}

/** Parse ADDRPORT\0[FLAGS] from a BEGIN cell body. */
fun parseBeginPayload(data: ByteArray): Pair<String, Int> {
    val nul = data.indexOf(0)
    require(nul > 0) { "BEGIN payload missing NUL" }
    val addrPort = data.copyOfRange(0, nul).decodeToString()
    val colon = addrPort.lastIndexOf(':')
    require(colon > 0) { "BEGIN address missing port: $addrPort" }
    val addr = addrPort.substring(0, colon)
    val port = addrPort.substring(colon + 1).toInt()
    return addr to port
}

fun buildRelayCell(command: RelayCommand, streamId: Int, data: ByteArray): RelayCell =
    RelayCell.build(command, streamId, data)
