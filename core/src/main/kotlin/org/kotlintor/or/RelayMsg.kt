package org.kotlintor.or

/** C Tor `relay_msg_t` — decoded relay message. */
data class RelayMsg(
    val command: Int,
    val streamId: Int,
    val length: Int,
    val body: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is RelayMsg && command == other.command && streamId == other.streamId &&
            length == other.length && body.contentEquals(other.body)
    override fun hashCode(): Int =
        command xor streamId xor length xor body.contentHashCode()
}
