package org.kotlintor.cell

import org.kotlintor.util.readU16be
import org.kotlintor.util.readU32be
import org.kotlintor.util.u16be
import org.kotlintor.util.u32be
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream

/**
 * Tor cell (link protocol ≥ 4): 4-byte circ_id + 1-byte command + payload.
 * Before VERSIONS negotiation, link protocol 3 uses 2-byte circ_ids.
 * Fixed cells: payload length 509. Variable cells: 2-byte length + payload.
 */
data class Cell(
    val circId: Long,
    val command: CellCommand,
    val payload: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is Cell && circId == other.circId && command == other.command &&
            payload.contentEquals(other.payload)

    override fun hashCode(): Int =
        circId.hashCode() xor command.hashCode() xor payload.contentHashCode()

    companion object {
        const val FIXED_PAYLOAD_LEN = 509
        /**
         * Max variable-cell payload accepted on the wire (DoS bound).
         * u16 allows 65535; we refuse larger-than-this before allocating.
         * Large enough for real CERTS/AUTHENTICATE; below unbounded peer floods.
         */
        const val MAX_VAR_CELL_PAYLOAD: Int = 32_768
        /** Fixed cell total size with 4-byte circ_id: 4 + 1 + 509. */
        const val CELL_NETWORK_SIZE_V4: Int = 514
        /** Fixed cell total size with 2-byte circ_id: 2 + 1 + 509. */
        const val CELL_NETWORK_SIZE_V3: Int = 512
        const val CIRC_ID_SIZE_V4: Int = 4
        const val CIRC_ID_SIZE_V3: Int = 2
        const val VAR_CELL_HEADER_SIZE_V4: Int = 7 // 4 circ + 1 cmd + 2 len
        const val VAR_CELL_HEADER_SIZE_V3: Int = 5 // 2 circ + 1 cmd + 2 len

        /** C Tor `get_cell_network_size` — wideCircIds ⇒ link protocol ≥ 4. */
        fun getCellNetworkSize(wideCircIds: Boolean = true): Int =
            if (wideCircIds) CELL_NETWORK_SIZE_V4 else CELL_NETWORK_SIZE_V3

        /** C Tor `get_circ_id_size`. */
        fun getCircIdSize(wideCircIds: Boolean = true): Int =
            if (wideCircIds) CIRC_ID_SIZE_V4 else CIRC_ID_SIZE_V3

        /** C Tor `get_var_cell_header_size`. */
        fun getVarCellHeaderSize(wideCircIds: Boolean = true): Int =
            if (wideCircIds) VAR_CELL_HEADER_SIZE_V4 else VAR_CELL_HEADER_SIZE_V3
    }
}

object CellCodec {
    fun encode(cell: Cell, circIdLen: Int = 4): ByteArray {
        require(circIdLen == 2 || circIdLen == 4)
        val header = when (circIdLen) {
            2 -> u16be(cell.circId.toInt() and 0xffff) + byteArrayOf(cell.command.id.toByte())
            else -> u32be(cell.circId) + byteArrayOf(cell.command.id.toByte())
        }
        return if (cell.command.variable) {
            header + u16be(cell.payload.size) + cell.payload
        } else {
            require(cell.payload.size <= Cell.FIXED_PAYLOAD_LEN)
            val padded = ByteArray(Cell.FIXED_PAYLOAD_LEN)
            cell.payload.copyInto(padded)
            header + padded
        }
    }

    fun write(out: OutputStream, cell: Cell, circIdLen: Int = 4) {
        out.write(encode(cell, circIdLen))
        out.flush()
    }

    /**
     * Read the next known cell. Unknown commands are drained and skipped
     * (tor-spec: cmds ≥128 are variable-length; others fixed 509).
     * Oversize variable payloads throw [java.io.IOException] (fail-closed).
     */
    fun read(input: InputStream, circIdLen: Int = 4): Cell {
        require(circIdLen == 2 || circIdLen == 4)
        while (true) {
            val circBytes = input.readNBytes(circIdLen)
            if (circBytes.size < circIdLen) throw EOFException("truncated circ_id")
            val cmdByte = input.read()
            if (cmdByte < 0) throw EOFException("truncated command")
            val circId = if (circIdLen == 2) readU16be(circBytes, 0).toLong() else readU32be(circBytes, 0)
            val command = CellCommand.fromIdOrNull(cmdByte)
            if (command == null) {
                drainUnknownPayload(input, cmdByte)
                continue
            }
            val payload = if (command.variable) {
                readVariablePayload(input)
            } else {
                val body = input.readNBytes(Cell.FIXED_PAYLOAD_LEN)
                if (body.size < Cell.FIXED_PAYLOAD_LEN) throw EOFException("truncated fixed payload")
                body
            }
            return Cell(circId, command, payload)
        }
    }

    private fun readVariablePayload(input: InputStream): ByteArray {
        val lenBytes = input.readNBytes(2)
        if (lenBytes.size < 2) throw EOFException("truncated length")
        val len = readU16be(lenBytes, 0)
        if (len > Cell.MAX_VAR_CELL_PAYLOAD) {
            throw java.io.IOException(
                "variable cell payload length $len exceeds max ${Cell.MAX_VAR_CELL_PAYLOAD}",
            )
        }
        val body = input.readNBytes(len)
        if (body.size < len) throw EOFException("truncated variable payload")
        return body
    }

    /** Spec: command ≥ 128 ⇒ variable; else fixed 509. */
    private fun drainUnknownPayload(input: InputStream, cmdByte: Int) {
        if (cmdByte >= 128) {
            val lenBytes = input.readNBytes(2)
            if (lenBytes.size < 2) throw EOFException("truncated unknown-var length")
            val len = readU16be(lenBytes, 0)
            if (len > Cell.MAX_VAR_CELL_PAYLOAD) {
                throw java.io.IOException(
                    "unknown variable cell cmd=$cmdByte length $len exceeds max",
                )
            }
            val body = input.readNBytes(len)
            if (body.size < len) throw EOFException("truncated unknown-var payload")
        } else {
            val body = input.readNBytes(Cell.FIXED_PAYLOAD_LEN)
            if (body.size < Cell.FIXED_PAYLOAD_LEN) throw EOFException("truncated unknown-fixed payload")
        }
    }
}

data class RelayCell(
    val command: RelayCommand,
    val recognized: Int,
    val streamId: Int,
    val digest: ByteArray,
    val length: Int,
    val data: ByteArray,
) {
    /** Classic tor1 / RELAY_CELL_FORMAT_V0 (cmd@0, stream@3, digest@5, len@9, data@11). */
    fun toPayload(): ByteArray {
        val out = ByteArray(Cell.FIXED_PAYLOAD_LEN)
        out[0] = command.id.toByte()
        out[1] = ((recognized ushr 8) and 0xff).toByte()
        out[2] = (recognized and 0xff).toByte()
        out[3] = ((streamId ushr 8) and 0xff).toByte()
        out[4] = (streamId and 0xff).toByte()
        require(digest.size == 4)
        digest.copyInto(out, 5)
        out[9] = ((length ushr 8) and 0xff).toByte()
        out[10] = (length and 0xff).toByte()
        require(data.size <= length)
        data.copyInto(out, 11, 0, data.size.coerceAtMost(length))
        return out
    }

    /**
     * Prop359 / CGO RELAY_CELL_FORMAT_V1 (`encode_v1_cell` in C Tor relay_msg.c):
     * bytes 0–15 reserved for CGO tag; cmd@16; len@17; optional stream@19; body follows.
     */
    fun toPayloadV1(pad: Boolean = true): ByteArray {
        val expectsStream = command.expectsStreamIdInV1()
        if (expectsStream) {
            require(streamId != 0) { "V1 ${command.name} requires non-zero streamId" }
        } else {
            require(streamId == 0) { "V1 ${command.name} must use streamId=0" }
        }
        val payloadOffset = if (expectsStream) V1_PAYLOAD_WITH_STREAM else V1_PAYLOAD_NO_STREAM
        val maxLen = Cell.FIXED_PAYLOAD_LEN - payloadOffset
        require(length <= maxLen) { "V1 relay body too long: $length > $maxLen" }
        require(data.size <= length)

        val out = ByteArray(Cell.FIXED_PAYLOAD_LEN)
        // Tag area [0..15] left zero; CGO clientOriginate fills nonce before encrypt.
        out[V1_CMD_OFFSET] = command.id.toByte()
        out[V1_LEN_OFFSET] = ((length ushr 8) and 0xff).toByte()
        out[V1_LEN_OFFSET + 1] = (length and 0xff).toByte()
        if (expectsStream) {
            out[V1_STREAM_OFFSET] = ((streamId ushr 8) and 0xff).toByte()
            out[V1_STREAM_OFFSET + 1] = (streamId and 0xff).toByte()
        }
        data.copyInto(out, payloadOffset, 0, data.size.coerceAtMost(length))
        if (pad) padRelayTail(out, payloadOffset + length)
        return out
    }

    companion object {
        /** C Tor V1 field offsets (relay_msg.c). */
        const val V1_CMD_OFFSET = 16
        const val V1_LEN_OFFSET = 17
        const val V1_STREAM_OFFSET = 19
        const val V1_PAYLOAD_NO_STREAM = 19
        const val V1_PAYLOAD_WITH_STREAM = 21
        private const val PAD_SKIP = 4

        fun parse(payload: ByteArray): RelayCell {
            require(payload.size >= 11)
            val cmd = RelayCommand.fromId(payload[0].toInt() and 0xff)
            val recognized = readU16be(payload, 1)
            val streamId = readU16be(payload, 3)
            val digest = payload.copyOfRange(5, 9)
            val length = readU16be(payload, 9)
            require(length <= payload.size - 11)
            val data = payload.copyOfRange(11, 11 + length)
            return RelayCell(cmd, recognized, streamId, digest, length, data)
        }

        /** Decode after CGO peel; [payload] is the full 509-byte plaintext cell. */
        fun parseV1(payload: ByteArray): RelayCell {
            require(payload.size >= Cell.FIXED_PAYLOAD_LEN) {
                "V1 cell must be ${Cell.FIXED_PAYLOAD_LEN} bytes, got ${payload.size}"
            }
            val cmd = RelayCommand.fromId(payload[V1_CMD_OFFSET].toInt() and 0xff)
            val length = readU16be(payload, V1_LEN_OFFSET)
            val expectsStream = cmd.expectsStreamIdInV1()
            val streamId: Int
            val payloadOffset: Int
            if (expectsStream) {
                streamId = readU16be(payload, V1_STREAM_OFFSET)
                payloadOffset = V1_PAYLOAD_WITH_STREAM
            } else {
                streamId = 0
                payloadOffset = V1_PAYLOAD_NO_STREAM
            }
            require(length <= Cell.FIXED_PAYLOAD_LEN - payloadOffset) {
                "V1 length $length exceeds max"
            }
            val data = payload.copyOfRange(payloadOffset, payloadOffset + length)
            return RelayCell(
                command = cmd,
                recognized = 0,
                streamId = streamId,
                digest = ByteArray(4),
                length = length,
                data = data,
            )
        }

        fun build(
            command: RelayCommand,
            streamId: Int,
            data: ByteArray,
        ): RelayCell = RelayCell(
            command = command,
            recognized = 0,
            streamId = streamId,
            digest = ByteArray(4),
            length = data.size,
            data = data,
        )

        /** C Tor `relay_cell_pad`: 4 zero bytes then random (proposal 289). */
        private fun padRelayTail(cell: ByteArray, endOfMessage: Int) {
            if (endOfMessage + PAD_SKIP >= Cell.FIXED_PAYLOAD_LEN) return
            val pad = org.kotlintor.util.SecureRandomSource.nextBytes(
                Cell.FIXED_PAYLOAD_LEN - (endOfMessage + PAD_SKIP),
            )
            pad.copyInto(cell, endOfMessage + PAD_SKIP)
        }
    }
}
