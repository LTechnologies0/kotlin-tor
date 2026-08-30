package org.kotlintor.or

/** C Tor `onion_handshake_state_t`. */
data class OnionHandshakeState(
    val circId: Long,
    val handshakeType: Int,
    val state: ByteArray = ByteArray(0),
) {
    override fun equals(other: Any?): Boolean =
        other is OnionHandshakeState && circId == other.circId && handshakeType == other.handshakeType &&
            state.contentEquals(other.state)
    override fun hashCode(): Int = circId.hashCode() xor handshakeType xor state.contentHashCode()
}
