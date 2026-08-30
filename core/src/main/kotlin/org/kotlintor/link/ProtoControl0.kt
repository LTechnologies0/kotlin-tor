package org.kotlintor.link

/**
 * Legacy control-port protocol-0 peek (C Tor `proto_control0.c`).
 *
 * Inventory: `L1:core/proto/proto_control0.c`
 *
 * C Tor `peek_buf_has_control0_command`: if ≥4 bytes available, read uint16
 * command at offset 2 (network order); cmd ≤ 0x14 ⇒ obsolete v0 framing
 * (not a valid v1 text control command).
 */
object ProtoControl0 {
    /** Max v0 control command id still treated as protocol-0 (inclusive). */
    const val CONTROL0_CMD_MAX: Int = 0x14

    /**
     * C Tor `peek_buf_has_control0_command` — true when [peek] looks like
     * obsolete binary control0 rather than control-spec text.
     */
    fun hasControl0Command(peek: ByteArray): Boolean {
        if (peek.size < 4) return false
        val cmd = ((peek[2].toInt() and 0xff) shl 8) or (peek[3].toInt() and 0xff)
        return cmd <= CONTROL0_CMD_MAX
    }

    fun rejectReason(): String = "obsolete control protocol 0; use control-spec text"

    /** 514 reply line for control-spec clients (closing connection). */
    fun rejectReplyLine(): String = "514 ${rejectReason()}\r\n"
}

/** Historical alias — prefer [ProtoControl0]. */
typealias Control0Peek = ProtoControl0
