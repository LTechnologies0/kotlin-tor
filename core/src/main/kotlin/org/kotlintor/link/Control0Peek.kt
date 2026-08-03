package org.kotlintor.link

/**
 * Legacy control-port protocol-0 peek (C Tor `proto_control0.c`).
 *
 * Inventory: `L1:core/proto/proto_control0.c`
 *
 * Modern controllers speak text control-spec; this only detects the obsolete
 * binary command framing Tor still rejects on the wire.
 */
object Control0Peek {
    /** True if [peek] looks like a control0 binary command (cmd in first byte). */
    fun hasControl0Command(peek: ByteArray): Boolean {
        if (peek.isEmpty()) return false
        // C Tor: first byte is a command code in a narrow range for v0 cells.
        val cmd = peek[0].toInt() and 0xff
        return cmd in 1..20 && (peek.size == 1 || peek.size >= 3)
    }

    fun rejectReason(): String = "obsolete control protocol 0; use control-spec text"
}
