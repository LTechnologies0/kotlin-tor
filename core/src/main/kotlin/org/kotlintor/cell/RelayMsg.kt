package org.kotlintor.cell

/**
 * Relay message view (C Tor `relay_msg.c` / `relay_msg_t`).
 *
 * Inventory: `L1:core/or/relay_msg.c`
 */
object RelayMsg {
    data class Msg(
        val command: RelayCommand,
        val streamId: Int,
        val length: Int,
        val body: ByteArray,
        val early: Boolean = false,
    ) {
        override fun equals(other: Any?): Boolean =
            other is Msg && command == other.command && streamId == other.streamId &&
                length == other.length && early == other.early && body.contentEquals(other.body)

        override fun hashCode(): Int =
            command.hashCode() xor streamId xor length xor early.hashCode() xor body.contentHashCode()
    }

    fun fromRelayCell(cell: RelayCell, early: Boolean = false): Msg =
        Msg(
            command = cell.command,
            streamId = cell.streamId,
            length = cell.length,
            body = cell.data.copyOf(cell.length.coerceAtMost(cell.data.size)),
            early = early,
        )

    fun toRelayCell(msg: Msg): RelayCell =
        RelayCell(
            command = msg.command,
            recognized = 0,
            streamId = msg.streamId,
            digest = ByteArray(4),
            length = msg.length,
            data = msg.body.copyOf(msg.length.coerceAtMost(msg.body.size)),
        )

    fun isBeginFamily(cmd: RelayCommand): Boolean =
        cmd == RelayCommand.BEGIN || cmd == RelayCommand.BEGIN_DIR

    fun isData(cmd: RelayCommand): Boolean = cmd == RelayCommand.DATA

    /** C Tor `relay_msg_clear` — zero body / length. */
    fun relayMsgClear(msg: Msg): Msg =
        msg.copy(length = 0, body = ByteArray(0))

    /** C Tor `relay_msg_copy`. */
    fun relayMsgCopy(msg: Msg): Msg =
        msg.copy(body = msg.body.copyOf())

    /** C Tor `relay_msg_free_` — GC no-op; returns null for C free idiom. */
    fun relayMsgFree_(msg: Msg?): Msg? = null
}
