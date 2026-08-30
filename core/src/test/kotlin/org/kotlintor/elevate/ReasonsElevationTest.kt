package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.kotlintor.cell.Reasons

/**
 * Elevates `L1:core/or/reasons.c` toward D3.
 *
 * Evidence: control / SOCKS5 / HTTP CONNECT / errno / TLS→ORCONN tables
 * match C Tor `reasons.c` + `or.h` constants.
 */
class ReasonsElevationTest {
    @Test
    fun `circuit_end_reason_to_control_string matches C Tor`() {
        assertEquals("TORPROTOCOL", Reasons.circuitEndToControl(Reasons.CIRC_TORPROTOCOL))
        assertEquals("TORPROTOCOL", Reasons.circuitEndToControl(Reasons.CIRC_TORPROTOCOL or Reasons.CIRC_REASON_FLAG_REMOTE))
        assertEquals("NOPATH", Reasons.circuitEndToControl(Reasons.CIRC_NOPATH))
        assertEquals("ORIGIN", Reasons.circuitEndToControl(Reasons.CIRC_AT_ORIGIN))
        assertEquals("MEASUREMENT_EXPIRED", Reasons.circuitEndToControl(Reasons.CIRC_MEASUREMENT_EXPIRED))
        assertEquals("IP_NOW_REDUNDANT", Reasons.circuitEndToControl(Reasons.CIRC_IP_NOW_REDUNDANT))
        assertNull(Reasons.circuitEndToControl(999))
    }

    @Test
    fun `stream_end_reason_to_control_string includes local reasons`() {
        assertEquals("MISC", Reasons.streamEndToControl(Reasons.STREAM_MISC))
        assertEquals("PRIVATE_ADDR", Reasons.streamEndToControl(Reasons.STREAM_PRIVATE_ADDR))
        assertEquals("ENTRYPOLICY", Reasons.streamEndToControl(Reasons.STREAM_ENTRYPOLICY))
        assertEquals("SOCKS_PROTOCOL", Reasons.streamEndToControl(Reasons.STREAM_SOCKSPROTOCOL))
        assertEquals("HTTP_PROTOCOL", Reasons.streamEndToControl(Reasons.STREAM_HTTPPROTOCOL))
        // Mask strips REMOTE flag
        assertEquals(
            "DONE",
            Reasons.streamEndToControl(Reasons.STREAM_DONE or Reasons.STREAM_FLAG_REMOTE),
        )
        assertNull(Reasons.streamEndToControl(999))
    }

    @Test
    fun `stream_end_reason_to_socks5_response matches C Tor`() {
        assertEquals(Reasons.SOCKS5_SUCCEEDED, Reasons.streamEndToSocks5(0))
        assertEquals(Reasons.SOCKS5_CONNECTION_REFUSED, Reasons.streamEndToSocks5(Reasons.STREAM_DONE))
        assertEquals(Reasons.SOCKS5_NOT_ALLOWED, Reasons.streamEndToSocks5(Reasons.STREAM_EXITPOLICY))
        assertEquals(Reasons.SOCKS5_NOT_ALLOWED, Reasons.streamEndToSocks5(Reasons.STREAM_ENTRYPOLICY))
        assertEquals(Reasons.SOCKS5_TTL_EXPIRED, Reasons.streamEndToSocks5(Reasons.STREAM_TIMEOUT))
        assertEquals(Reasons.SOCKS5_HOST_UNREACHABLE, Reasons.streamEndToSocks5(Reasons.STREAM_NOROUTE))
        assertEquals(Reasons.SOCKS5_NET_UNREACHABLE, Reasons.streamEndToSocks5(Reasons.STREAM_NET_UNREACHABLE))
        assertEquals(Reasons.SOCKS5_CONNECTION_REFUSED, Reasons.streamEndToSocks5(Reasons.STREAM_CONNRESET))
    }

    @Test
    fun `orconn_end_reason_to_control_string uses or_h codes`() {
        assertEquals("DONE", Reasons.orconnEndToControl(Reasons.ORCONN_DONE))
        assertEquals("CONNECTREFUSED", Reasons.orconnEndToControl(Reasons.ORCONN_REFUSED))
        assertEquals("IDENTITY", Reasons.orconnEndToControl(Reasons.ORCONN_IDENTITY))
        assertEquals("CONNECTRESET", Reasons.orconnEndToControl(Reasons.ORCONN_CONNRESET))
        assertEquals("TLS_ERROR", Reasons.orconnEndToControl(Reasons.ORCONN_TLS_ERROR))
        assertEquals("PT_MISSING", Reasons.orconnEndToControl(Reasons.ORCONN_PT_MISSING))
        assertEquals("MISC", Reasons.orconnEndToControl(Reasons.ORCONN_MISC))
        assertEquals("", Reasons.orconnEndToControl(0))
        assertEquals("UNKNOWN", Reasons.orconnEndToControl(99))
    }

    @Test
    fun `errno and tls tables`() {
        assertEquals(Reasons.STREAM_DONE, Reasons.errnoToStreamEndReason(Reasons.Errno.EPIPE))
        assertEquals(Reasons.STREAM_CONNECTREFUSED, Reasons.errnoToStreamEndReason(Reasons.Errno.ECONNREFUSED))
        assertEquals(Reasons.STREAM_TIMEOUT, Reasons.errnoToStreamEndReason(Reasons.Errno.ETIMEDOUT))
        assertEquals(Reasons.STREAM_RESOURCELIMIT, Reasons.errnoToStreamEndReason(Reasons.Errno.ENOMEM))
        assertEquals(Reasons.ORCONN_REFUSED, Reasons.errnoToOrconnEndReason(Reasons.Errno.ECONNREFUSED))
        assertEquals(Reasons.ORCONN_NO_ROUTE, Reasons.errnoToOrconnEndReason(Reasons.Errno.ENETUNREACH))
        assertEquals(
            Reasons.ORCONN_IO_ERROR,
            Reasons.tlsErrorToOrconnEndReason(Reasons.TOR_TLS_ERROR_IO),
        )
        assertEquals(
            Reasons.ORCONN_DONE,
            Reasons.tlsErrorToOrconnEndReason(Reasons.TOR_TLS_CLOSE),
        )
        assertEquals(
            Reasons.ORCONN_TLS_ERROR,
            Reasons.tlsErrorToOrconnEndReason(Reasons.TOR_TLS_ERROR_MISC),
        )
    }

    @Test
    fun `http connect and socks response strings`() {
        assertEquals("HTTP/1.0 200 OK\r\n", Reasons.endReasonToHttpConnectResponseLine(0))
        assertEquals(
            "HTTP/1.0 504 Gateway Timeout\r\n",
            Reasons.endReasonToHttpConnectResponseLine(Reasons.STREAM_TIMEOUT),
        )
        assertEquals(
            "HTTP/1.0 403 Forbidden (entry policy violation)\r\n",
            Reasons.endReasonToHttpConnectResponseLine(Reasons.STREAM_ENTRYPOLICY),
        )
        assertEquals("connection accepted", Reasons.socks5ResponseCodeToString(0x00))
        assertEquals("TTL expired", Reasons.socks5ResponseCodeToString(0x06))
        assertEquals("connection accepted", Reasons.socks4ResponseCodeToString(0x5a))
        assertEquals("closed normally", Reasons.streamEndToString(Reasons.STREAM_DONE))
        assertEquals("MALFORMED", Reasons.streamEndToString(-1))
    }
}
