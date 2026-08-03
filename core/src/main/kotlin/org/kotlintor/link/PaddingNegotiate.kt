package org.kotlintor.link

import org.kotlintor.cell.Cell
import org.kotlintor.cell.CellCommand
import org.kotlintor.util.u16be

/**
 * Prop254 / link protocol v5 PADDING_NEGOTIATE cell.
 *
 * | Command | 1 | 1=start, 2=stop |
 * | ito_low_ms | 2 |
 * | ito_high_ms | 2 |
 */
object PaddingNegotiate {
    const val COMMAND_START: Int = 1
    const val COMMAND_STOP: Int = 2

    fun start(itoLowMs: Int = 1_500, itoHighMs: Int = 9_500): Cell {
        val payload = ByteArray(org.kotlintor.cell.Cell.FIXED_PAYLOAD_LEN)
        payload[0] = COMMAND_START.toByte()
        u16be(itoLowMs).copyInto(payload, 1)
        u16be(itoHighMs).copyInto(payload, 3)
        return Cell(0, CellCommand.PADDING_NEGOTIATE, payload)
    }

    fun stop(): Cell {
        val payload = ByteArray(org.kotlintor.cell.Cell.FIXED_PAYLOAD_LEN)
        payload[0] = COMMAND_STOP.toByte()
        return Cell(0, CellCommand.PADDING_NEGOTIATE, payload)
    }

    fun parse(payload: ByteArray): Triple<Int, Int, Int> {
        require(payload.isNotEmpty())
        val cmd = payload[0].toInt() and 0xff
        val low = if (payload.size >= 3) ((payload[1].toInt() and 0xff) shl 8) or (payload[2].toInt() and 0xff) else 0
        val high = if (payload.size >= 5) ((payload[3].toInt() and 0xff) shl 8) or (payload[4].toInt() and 0xff) else 0
        return Triple(cmd, low, high)
    }
}

/**
 * AUTH_CHALLENGE parser (tor-spec). Method 3 = Ed25519-SHA256-RFC5705.
 */
object AuthChallenge {
    const val METHOD_ED25519_SHA256_RFC5705: Int = 3

    data class Parsed(val challenge: ByteArray, val methods: List<Int>)

    fun parse(payload: ByteArray): Parsed {
        require(payload.size >= 34)
        val challenge = payload.copyOfRange(0, 32)
        val n = ((payload[32].toInt() and 0xff) shl 8) or (payload[33].toInt() and 0xff)
        val methods = mutableListOf<Int>()
        var i = 34
        repeat(n) {
            if (i + 2 > payload.size) return@repeat
            methods += ((payload[i].toInt() and 0xff) shl 8) or (payload[i + 1].toInt() and 0xff)
            i += 2
        }
        return Parsed(challenge, methods)
    }

    /** Responder advertisement: challenge + method 3. */
    fun encode(challenge: ByteArray = org.kotlintor.util.SecureRandomSource.nextBytes(32)): ByteArray {
        require(challenge.size == 32)
        return challenge + byteArrayOf(0, 1, 0, METHOD_ED25519_SHA256_RFC5705.toByte())
    }
}
