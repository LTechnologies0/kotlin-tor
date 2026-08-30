package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.link.Control0Peek

/**
 * Elevates `L1:core/proto/proto_control0.c` toward D3.
 *
 * Evidence: peek matches C Tor `peek_buf_has_control0_command` (uint16@+2 ≤ 0x14);
 * ControlServer rejects on live accept path.
 */
class ProtoControl0ElevationTest {
    @Test
    fun `peek_buf_has_control0_command matches C Tor`() {
        assertFalse(Control0Peek.hasControl0Command(byteArrayOf(0, 0, 0))) // <4
        assertTrue(Control0Peek.hasControl0Command(byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0, 0)))
        assertTrue(Control0Peek.hasControl0Command(byteArrayOf(0, 0, 0, Control0Peek.CONTROL0_CMD_MAX.toByte())))
        assertFalse(Control0Peek.hasControl0Command(byteArrayOf(0, 0, 0, 0x15)))
        // Text control-spec: "AUTH…" → cmd = 0x5448 ('T''H') ≫ 0x14
        assertFalse(Control0Peek.hasControl0Command("AUTHENTICATE".toByteArray()))
        assertEquals("514 ${Control0Peek.rejectReason()}\r\n", Control0Peek.rejectReplyLine())
    }
}
