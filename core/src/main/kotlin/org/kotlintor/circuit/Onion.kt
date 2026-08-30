package org.kotlintor.circuit

import org.kotlintor.crypto.OnionCrypto
import org.kotlintor.util.readU16be
import org.kotlintor.util.u16be

/**
 * CREATE / CREATE2 onionskin helpers (C Tor `onion.c`).
 *
 * Inventory: `L1:core/or/onion.c`
 */
object Onion {
    data class CreateCell(
        val handshakeType: Int,
        val onionSkin: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean =
            other is CreateCell && handshakeType == other.handshakeType &&
                onionSkin.contentEquals(other.onionSkin)

        override fun hashCode(): Int = handshakeType xor onionSkin.contentHashCode()
    }

    /** Encode CREATE2 handshake type + length + skin. */
    fun encodeCreate2(type: Int, skin: ByteArray): ByteArray =
        u16be(type and 0xffff) + u16be(skin.size and 0xffff) + skin

    /** Parse CREATE2 payload. */
    fun parseCreate2(payload: ByteArray): CreateCell? {
        if (payload.size < 4) return null
        val type = readU16be(payload, 0)
        val len = readU16be(payload, 2)
        if (payload.size < 4 + len) return null
        return CreateCell(type, payload.copyOfRange(4, 4 + len))
    }

    fun createFastSkin(): Pair<OnionCrypto.ClientState.Fast, ByteArray> =
        OnionCrypto.onionSkinCreateFast()

    fun handshakeTypeName(type: Int): String = OnionCrypto.handshakeName(type)

    data class CreatedCell(val reply: ByteArray) {
        override fun equals(other: Any?): Boolean =
            other is CreatedCell && reply.contentEquals(other.reply)
        override fun hashCode(): Int = reply.contentHashCode()
    }

    data class ExtendCell(
        val linkSpecifiers: ByteArray = ByteArray(0),
        val create: CreateCell,
    )

    data class ExtendedCell(val created: CreatedCell)

    /** C Tor `create_cell_init`. */
    fun createCellInit(handshakeType: Int, onionSkin: ByteArray): CreateCell =
        CreateCell(handshakeType, onionSkin.copyOf())

    /** C Tor `create_cell_parse` — CREATE2 payload. */
    fun createCellParse(payload: ByteArray): CreateCell? = parseCreate2(payload)

    /** C Tor `create_cell_format`. */
    fun createCellFormat(cell: CreateCell): ByteArray =
        encodeCreate2(cell.handshakeType, cell.onionSkin)

    /** C Tor `create_cell_format_relayed` — same wire as format for CREATE2. */
    fun createCellFormatRelayed(cell: CreateCell): ByteArray = createCellFormat(cell)

    /** C Tor `created_cell_parse`. */
    fun createdCellParse(payload: ByteArray): CreatedCell =
        CreatedCell(payload.copyOf())

    /** C Tor `created_cell_format`. */
    fun createdCellFormat(cell: CreatedCell): ByteArray = cell.reply.copyOf()

    /** C Tor `extend_cell_format` — returns CREATE2 body embedded in EXTEND2. */
    fun extendCellFormat(cell: ExtendCell): ByteArray =
        cell.linkSpecifiers + createCellFormat(cell.create)

    /** C Tor `extended_cell_format`. */
    fun extendedCellFormat(cell: ExtendedCell): ByteArray =
        createdCellFormat(cell.created)

    /** C Tor `extended_cell_parse`. */
    fun extendedCellParse(payload: ByteArray): ExtendedCell =
        ExtendedCell(createdCellParse(payload))
}
